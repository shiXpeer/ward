# Миграция на 0.4

Этот прежний журнал запуска относится к JSON feed v3 и manifest v2.
Он не является инструкцией для текущей версии. Используйте команды из
[README](../README.ru.md) и [протокол v3](distribution.md).
Новые замеры: [компактная база](verification/compact-0.4.md).

<details><summary>Исторический запуск</summary>

# Проверка на настоящих данных на Mac

Все команды выполняются из каталога проекта. Root и sudo не нужны. Инвентаризация
хоста не отправляется. Ничего не устанавливается и не обновляется в ОС.

Собрать оба приложения:

```sh
# Run from the repository root.
make build
```

Быстро проверить настоящие источники (не демонстрационные данные):

```sh
bin/shixpeer-ward-beacon check-sources -sources configs/beacon.quickstart.json
```

Команда печатает JSON с количеством записей и завершится с ненулевым кодом, если
хотя бы один источник не скачался или не разобрался. Подробности ошибки — stderr.
Повторные запуски снова скачивают полные общие базы.

Для полного набора Ubuntu/Debian/macOS и популярных зависимостей:

```sh
bin/shixpeer-ward-beacon check-sources -sources configs/beacon.default.json
```

Первый полный проход занимает минуты, расходует сотни мегабайт трафика и требует
много памяти. Распакованный Canonical OSV — примерно 12,3 ГБ исходного JSON;
нормализованные данные тоже велики. Для первого запуска используйте quickstart.
Default уже включает прямые CVE/GHSA. Extended добавляет дополнительные OSV-архивы; данные повторяются
между источниками, а требования к ресурсам растут.

## Сохранить, подписать и отдать агенту

Используется новый каталог `.local/real-v3`, чтобы не смешивать старое состояние с
новым форматом. Команда init выполняется один раз и не перезаписывает ключи.

```sh
mkdir -p .local/real-v3
bin/shixpeer-ward-beacon init -pki .local/real-v3/pki

bin/shixpeer-ward-beacon sync \
  -sources configs/beacon.quickstart.json \
  -state .local/real-v3/beacon \
  -out .local/real-v3/public \
  -signing-key .local/real-v3/pki/signing.key

bin/shixpeer-ward-beacon status -state .local/real-v3/beacon
```

После успешного status запустить сервер в первом терминале:

```sh
bin/shixpeer-ward-beacon serve \
  -state .local/real-v3/beacon \
  -out .local/real-v3/public \
  -tls-cert .local/real-v3/pki/server.crt \
  -tls-key .local/real-v3/pki/server.key
```

Во втором терминале:

```sh
# Run from the repository root.
bin/shixpeer-ward-agent pull \
  -state .local/real-v3/agent \
  -feed-url https://localhost:8443/v1/manifest.json \
  -ca-file .local/real-v3/pki/ca.crt \
  -trusted-key .local/real-v3/pki/feed.pub
```

Вы получите `.local/real-v3/agent/feed.json` и число принятых записей. Агент
проверяет HTTPS, подпись, срок действия, размеры, хеши всех частей и откат ревизии.
Неверная часть не заменяет установленную базу. Сервер остановить Ctrl+C.
Папки `.local/` и `bin/` игнорируются репозиторием.

Для полного набора замените quickstart на default в команде sync. Для периодической
работы используйте `run` с теми же путями, sources, signing-key и TLS-флагами:
`-sync-interval 24h -ttl 72h`. Срок подписи должен превышать интервал и время
синхронизации. Не ставьте большие полные обновления каждую минуту.

Это проверка работающего конвейера базы уязвимостей. Сбор всех установленных
пакетов/контейнеров и окончательное локальное сопоставление версий ещё не реализованы;
число загруженных CVE не является результатом проверки безопасности вашего Mac.

</details>
