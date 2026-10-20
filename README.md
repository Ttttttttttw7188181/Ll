# Antinet — country-only Sing-box config

Автоматически собирает один Sing-box JSON из публичных VLESS URI. В конфиге только группы по странам и группа **Auto** (urltest выбирает узел с лучшим откликом). Никаких российских белых/чёрных списков.

## Источники

- https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt
- https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt
- https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl

Недоступный источник пропускается и отмечается в `dist/report.json`. Ссылки VLESS без страны в имени пытается определить по IP. Не поддерживаемые типы транспорта (например XHTTP/packet-up) исключаются, чтобы не публиковать заведомо несовместимые узлы.

## Raw URL

После первого успешного запуска Actions:
`https://raw.githubusercontent.com/Ttttttttttw7188181/Ll/main/dist/antinet-countries.json`

## Обновление

GitHub Actions запускается каждые 6 часов, а также вручную через **Actions → Build country-only Antinet config → Run workflow**. Первый запуск можно выполнить вручную после добавления файлов.

## Важно

Это полноценный Sing-box JSON с TUN inbound. Совместимость импорта именно как подписки зависит от версии Antinet. Группа Auto тестирует доступность через URLTest, но GitHub Actions не проверяет доступность из вашей сети/оператора; окончательную проверку сделайте в Antinet и на https://browserleaks.com/ip.
