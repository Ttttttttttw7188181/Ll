#!/usr/bin/env python3
"""Build a country-grouped Sing-box config from public VLESS URI lists."""
import json, os, re, socket, sys, time
from urllib.parse import urlsplit, parse_qs, unquote
from urllib.request import Request, urlopen

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl",
]
OUT = "dist/antinet-countries.json"
UA = "AntinetCountryBuilder/1.0"
FLAGS = {
 "US":"United States","GB":"United Kingdom","DE":"Germany","FI":"Finland","FR":"France",
 "NL":"Netherlands","SE":"Sweden","NO":"Norway","DK":"Denmark","EE":"Estonia",
 "LV":"Latvia","LT":"Lithuania","PL":"Poland","CZ":"Czechia","CH":"Switzerland",
 "AT":"Austria","BE":"Belgium","ES":"Spain","IT":"Italy","PT":"Portugal","IE":"Ireland",
 "IS":"Iceland","RO":"Romania","BG":"Bulgaria","GR":"Greece","TR":"Turkey","CY":"Cyprus",
 "IL":"Israel","AE":"United Arab Emirates","SG":"Singapore","JP":"Japan","KR":"South Korea",
 "HK":"Hong Kong","TW":"Taiwan","IN":"India","ID":"Indonesia","TH":"Thailand","VN":"Vietnam",
 "MY":"Malaysia","PH":"Philippines","AU":"Australia","NZ":"New Zealand","CA":"Canada",
 "MX":"Mexico","BR":"Brazil","AR":"Argentina","CL":"Chile","KZ":"Kazakhstan","UA":"Ukraine",
 "RU":"Russia","MD":"Moldova","GE":"Georgia","AM":"Armenia","AZ":"Azerbaijan","RS":"Serbia",
 "HR":"Croatia","SI":"Slovenia","SK":"Slovakia","HU":"Hungary","AL":"Albania","BA":"Bosnia",
 "MK":"North Macedonia","LU":"Luxembourg","MT":"Malta","EG":"Egypt","ZA":"South Africa",
}
FLAG_RE = re.compile("[\\U0001F1E6-\\U0001F1FF]{2}")
COUNTRY_WORDS = sorted(FLAGS.values(), key=len, reverse=True)

def fetch(url):
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", "replace")

def uri_country(uri):
    frag = unquote(urlsplit(uri).fragment or "").replace("_", " ")
    m = FLAG_RE.search(frag)
    if m:
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in m.group())
        if code in FLAGS:
            return FLAGS[code]
    low = frag.casefold()
    for country in COUNTRY_WORDS:
        if country.casefold() in low:
            return country
    # Common aliases used in server names.
    aliases = {"uk":"United Kingdom", "england":"United Kingdom", "usa":"United States",
               "holland":"Netherlands", "uae":"United Arab Emirates", "korea":"South Korea"}
    for alias, country in aliases.items():
        if re.search(r"\b" + re.escape(alias) + r"\b", low):
            return country
    return None

def identity(uri):
    p = urlsplit(uri)
    q = parse_qs(p.query, keep_blank_values=True)
    # Ignore fragment, fingerprint and ALPN variations: they often duplicate the same endpoint.
    ignored = {"fp", "alpn"}
    qs = tuple(sorted((k, tuple(v)) for k, v in q.items() if k not in ignored))
    return (p.scheme, p.username, p.hostname, p.port, qs)

def geo_country(host):
    # Best-effort fallback for links without a country label.
    try:
        ip = socket.gethostbyname(host)
        data = json.loads(fetch("http://ip-api.com/json/" + ip + "?fields=status,country"))
        if data.get("status") == "success":
            return data.get("country")
    except Exception:
        pass
    return None

def node_from_uri(uri, index, country):
    p = urlsplit(uri)
    if p.scheme.lower() != "vless" or not p.hostname or not p.port or not p.username:
        return None
    q = parse_qs(p.query, keep_blank_values=True)
    def one(k, default=""):
        return q.get(k, [default])[0]
    net = one("type", "tcp").lower()
    # Sing-box does not implement XHTTP's packet-up mode; do not publish broken outbounds.
    if net in ("xhttp", "splithttp"):
        return None
    tag = "%s %03d" % (country, index)
    out = {"type":"vless", "tag":tag, "server":p.hostname, "server_port":p.port,
           "uuid":p.username, "packet_encoding":"xudp"}
    flow = one("flow")
    if flow:
        out["flow"] = flow
    security = one("security").lower()
    if security in ("tls", "reality"):
        tls = {"enabled":True, "server_name":one("sni") or p.hostname}
        alpn = one("alpn")
        if alpn:
            tls["alpn"] = [x for x in alpn.split(",") if x]
        fp = one("fp")
        if fp:
            tls["utls"] = {"enabled":True, "fingerprint":fp}
        if security == "reality":
            pub, sid = one("pbk"), one("sid")
            if not pub:
                return None
            tls["reality"] = {"enabled":True, "public_key":pub}
            if sid:
                tls["reality"]["short_id"] = sid
        out["tls"] = tls
    elif security not in ("", "none"):
        return None
    if net == "ws":
        tr = {"type":"ws"}
        host = one("host")
        path = one("path")
        if host:
            tr["headers"] = {"Host":host}
        if path:
            tr["path"] = path
        out["transport"] = tr
    elif net == "grpc":
        service = one("serviceName") or one("service_name")
        tr = {"type":"grpc"}
        if service:
            tr["service_name"] = service
        out["transport"] = tr
    elif net in ("httpupgrade", "http-upgrade"):
        tr = {"type":"httpupgrade"}
        host, path = one("host"), one("path")
        if host: tr["host"] = [host]
        if path: tr["path"] = path
        out["transport"] = tr
    elif net in ("http", "h2"):
        tr = {"type":"http"}
        host, path = one("host"), one("path")
        if host: tr["host"] = [host]
        if path: tr["path"] = path
        out["transport"] = tr
    elif net not in ("tcp", "raw", ""):
        return None
    return out

def main():
    uris, seen = [], set()
    source_status = []
    for source in SOURCES:
        try:
            body = fetch(source)
            count = 0
            for line in body.splitlines():
                uri = line.strip()
                if not uri.lower().startswith("vless://"):
                    continue
                count += 1
                try:
                    key = identity(uri)
                except Exception:
                    continue
                if key not in seen:
                    seen.add(key)
                    uris.append(uri)
            source_status.append({"url":source,"parsed_lines":count,"status":"ok"})
        except Exception as e:
            source_status.append({"url":source,"status":"unavailable","error":str(e)[:180]})
            print("WARN source unavailable:", source, str(e), file=sys.stderr)

    grouped = {}
    unlabelled = []
    for uri in uris:
        country = uri_country(uri)
        if country:
            grouped.setdefault(country, []).append(uri)
        else:
            unlabelled.append(uri)
    # Geo-detect unlabeled entries, one lookup per host.
    geo_cache = {}
    for uri in unlabelled:
        host = urlsplit(uri).hostname or ""
        if host not in geo_cache:
            geo_cache[host] = geo_country(host)
        country = geo_cache[host]
        if country:
            grouped.setdefault(country, []).append(uri)

    nodes, country_tags = [], {}
    dropped = 0
    for country in sorted(grouped):
        country_nodes = []
        for uri in grouped[country]:
            node = node_from_uri(uri, len(nodes) + len(country_nodes) + 1, country)
            if node:
                country_nodes.append(node)
            else:
                dropped += 1
        if not country_nodes:
            continue
        nodes.extend(country_nodes)
        country_tags[country] = [n["tag"] for n in country_nodes]

    if not nodes:
        raise SystemExit("No compatible, country-labelled VLESS servers found; refusing to overwrite output.")
    # Keep Auto and country selectors as top-level outbounds so clients can expose each as a group.
    outbounds = []
    outbounds.append({"type":"urltest","tag":"Авто","outbounds":[n["tag"] for n in nodes],
                      "url":"https://www.gstatic.com/generate_204","interval":"5m","tolerance":50,"interrupt_exist_connections":False})
    for country, tags in country_tags.items():
        outbounds.append({"type":"selector","tag":"Страна | " + country,"outbounds":tags,"default":tags[0]})
    outbounds.extend(nodes)
    outbounds.extend([{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}])
    config = {
      "log":{"level":"warn","timestamp":True},
      "dns":{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1"},{"type":"local","tag":"dns-local"}],
             "final":"dns-remote","strategy":"prefer_ipv4"},
      "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":True,"strict_route":True,"stack":"mixed"}],
      "outbounds":outbounds,
      "route":{"auto_detect_interface":True,"final":"Авто"}
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, OUT)
    report = {"generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "unique_vless_uris":len(uris),"compatible_nodes":len(nodes),
              "countries":{c:len(tags) for c,tags in country_tags.items()},
              "dropped_unsupported_or_invalid":dropped,"sources":source_status}
    with open("dist/report.json","w",encoding="utf-8") as f:
        json.dump(report,f,ensure_ascii=False,indent=2)
        f.write("\n")
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__ == "__main__":
    main()
