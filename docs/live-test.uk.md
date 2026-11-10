# Міграція на 0.4

> Historical verification notes. For deployment and current procedures, see the [documentation index](README.md).

Цей колишній журнал запуску стосується JSON feed v3 і manifest v2.
Він не є інструкцією для поточної версії. Використовуйте команди з
[README](../README.uk.md) і [протокол v3](distribution.md).
Нові заміри: [компактна база](verification/compact-0.4.md).

<details><summary>Історичний запуск</summary>

# Перевірка на справжніх даних на Mac

Усі команди виконуються з каталогу проєкту. Root і sudo не потрібні. Інвентаризація
хоста не надсилається. Нічого не встановлюється і не оновлюється в ОС.

Зібрати обидві програми:

```sh
# Запускайте команди з каталогу репозиторію.
make build
```

Швидко перевірити справжні джерела (не демонстраційні дані):

```sh
bin/shixpeer-ward-beacon check-sources -sources configs/beacon.quickstart.json
```

Команда друкує JSON із кількістю записів і завершиться ненульовим кодом, якщо
хоча б одне джерело не завантажилося або не розібралося. Подробиці помилки — stderr.
Повторні запуски знову завантажують повні спільні бази.

Для повного набору Ubuntu/Debian/macOS і популярних залежностей:

```sh
bin/shixpeer-ward-beacon check-sources -sources configs/beacon.default.json
```

Перший повний прохід триває хвилини, витрачає сотні мегабайт трафіку і потребує
багато пам'яті. Розпакований Canonical OSV — приблизно 12,3 ГБ вихідного JSON;
нормалізовані дані теж великі. Для першого запуску використовуйте quickstart.
Default уже включає прямі CVE/GHSA. Extended додає додаткові архіви OSV; дані повторюються
між джерелами, а вимоги до ресурсів зростають.

## Зберегти, підписати і віддати агенту

Використовується новий каталог `.local/real-v3`, щоб не змішувати старий стан із
новим форматом. Команда init виконується один раз і не перезаписує ключі.

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

Після успішного status запустіть сервер у першому терміналі:

```sh
bin/shixpeer-ward-beacon serve \
  -state .local/real-v3/beacon \
  -out .local/real-v3/public \
  -tls-cert .local/real-v3/pki/server.crt \
  -tls-key .local/real-v3/pki/server.key
```

У другому терміналі:

```sh
# Запускайте команди з каталогу репозиторію.
bin/shixpeer-ward-agent pull \
  -state .local/real-v3/agent \
  -feed-url https://localhost:8443/v1/manifest.json \
  -ca-file .local/real-v3/pki/ca.crt \
  -trusted-key .local/real-v3/pki/feed.pub
```

Ви отримаєте `.local/real-v3/agent/feed.json` і кількість прийнятих записів. Агент
перевіряє HTTPS, підпис, строк дії, розміри, хеші всіх частин і відкат ревізії.
Невірна частина не замінює встановлену базу. Сервер зупинити Ctrl+C.
Каталоги `.local/` і `bin/` ігноруються репозиторієм.

Для повного набору замініть quickstart на default у команді sync. Для періодичної
роботи використовуйте `run` з тими самими шляхами, sources, signing-key і прапорцями TLS:
`-sync-interval 24h -ttl 72h`. Строк підпису має перевищувати інтервал і час
синхронізації. Не ставте великі повні оновлення щохвилини.

Це перевірка робочого конвеєра бази вразливостей. Збір усіх встановлених
пакетів і контейнерів та остаточне локальне зіставлення версій ще не реалізовані;
кількість завантажених CVE не є результатом перевірки безпеки вашого Mac.

</details>
