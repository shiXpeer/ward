# Ubuntu: Beacon, встановлення агента і перший звіт

Для Ubuntu 24.04 зі systemd, amd64 або arm64. Команди нижче запускає адміністратор.
Розробка на Mac не означає, що щось уже встановлено на ваших серверах.
Проєкт: https://shixpeer.com. Go на серверах не потрібен: використовуються готові бінарники.
Англійською: [ubuntu-deployment.md](ubuntu-deployment.md).

## Швидкий шлях із Mac

Готовий архів лежить у `dist/shixpeer-ward-ubuntu.tar.gz` (перезібрати:
`make ubuntu-bundle`). Для нового Beacon зі встановленим `acl`:

```bash
bash packaging/shixpeer-ward-deploy-beacon.sh BEACON_SSH_HOST https://BEACON_HOST:8443
```

Якщо Beacon уже встановлено, цей крок пропустіть. Після першої успішної публікації
виконайте одну команду на кожен сервер агента:

```bash
bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
```

Обидва SSH-хости приймають необов'язковий порт, наприклад
`beacon.example.org:2222` і `agent.example.org:2200`. Без порту застосовуються
налаштування OpenSSH. HTTPS-адреса в останньому аргументі задається окремо.

Використовуйте SSH-ключі і заздалегідь перевірені записи обох хостів у known_hosts.
На агенті потрібні curl і OpenSSL. Скрипти не змінюють SSH і фаєрвол. Нижче наведено
ручний варіант для діагностики і випадків, коли прямого SSH-доступу немає.

## Що саме перевіряється

Агент локально збирає встановлені dpkg-пакети і версії вихідних пакетів,
ОС, ядро, служби, TCP/UDP-сокети, що слухають, і доступних власників процесів,
метадані запущених контейнерів Docker і їхні опубліковані порти, глобальні
пакети npm/Python. Підтримувані правила звіряються з підписаною локальною базою.
Нічого з інвентаризації на Beacon не надсилається. Усі агенти отримують спільну базу.

Для робочого ядра Ubuntu використовується `/proc/version_signature`, для Debian —
підтримуваний підпис збірки `uname -v`. Для підписаних образів Ubuntu вихідний
пакет береться з Built-Using. Версія встановленого пакета не підставляється замість
версії завантаженого ядра. Якщо зв'язати їх не можна, буде UNRESOLVED або NOT_CHECKED.
Сигнал `/var/run/reboot-required` і відоме відставання завантаженої версії
показуються як попередження: після оновлення може знадобитися reboot.

Це частковий сканер. Невідомі продукти, складні умови CVE, пакети всередині
контейнерів, проєктні lockfile/venv і непідтримувані схеми версій лишаються явно
неперевіреними. Порт не можна «оновити»: звіт показує прив'язку і власника,
а зовнішня доступність залежить від фаєрвола, NAT і хмарних правил.
Якщо ss/iproute2 відсутні, читаються таблиці /proc/net, без атрибуції власників. Перевірки ззовні немає.
Збіг версійного правила — підстава перевірити advisory і оновлення,
а не доказ успішної експлуатації. Автооновлень ОС і програм, reboot,
змін UFW, фаєрвола, SSH і docker exec немає.

## Де лежать дані

Типово весь стан Ward перебуває в HOME **користувача процесу**:

```text
~/.shixpeer.ward/
  bin/                      встановлені бінарники і службові скрипти
  config/agent.json         адреса Beacon, публічний ключ, каталог даних
  config/ca.crt             довірений публічний CA, якщо використовується приватний HTTPS
  agent/database/           підписана локальна база і checkpoint від відкату
  agent/snapshot.json       локальний знімок
  agent/report.md           читабельний звіт
  agent/report.json         повний звіт і докази
  beacon/                   стан, кеш і публічна база видавця (на Beacon)
  pki/                      ключі лише на відповідному сервері й користувачі
  releases/                 Linux-бінарники для роздачі (на Beacon)
  logs/agent.log            журнал звітів демона, до 4 МіБ плюс попередній файл
```

Звичайний запуск — HOME поточного користувача; `sudo -H` — `/root`. Демон працює
не від root. За `--user ubuntu` це `/home/ubuntu/.shixpeer.ward/`; за створеного
встановлювачем `shixpeer-ward-agent` — `/home/shixpeer-ward-agent/.shixpeer.ward/`. Бази і звіти не лежать
у checkout, `/var/lib` або поруч із вихідними кодами. Файли systemd unit природно
встановлюються в `/etc/systemd/system`; journal запуску й помилок служби зберігає сам systemd; короткі звіти демона
пишуться в домашній logs/agent.log, а не в journal.
Прапорці `-state`, `-config`, `-report-dir` лишаються явними розширеними перевизначеннями.

## 1. Зібрати архів на машині розробки

У корені репозиторію:

```bash
make check
make ubuntu-bundle
```

Вийде `dist/shixpeer-ward-ubuntu.tar.gz`: обидві програми для Linux amd64/arm64,
налаштування джерел і встановлювач Beacon. `dist/` виключено з репозиторію.
Це dev-збірка; не видавайте її за опублікований стабільний реліз.

## 2. Підготувати окремий сервер Beacon

У прикладах `BEACON_HOST` — ваш справжній DNS або IPv4. Для приватної мережі зручно
використовувати стабільну внутрішню адресу; TLS-сертифікат створюється саме для неї.
Встановлювач використовує порт 8443. Жодного публічного офіційного endpoint Ward
типово не існує.

На Beacon створіть каталог для архіву:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
```

З Mac передайте архів через SSH із перевіреним host key:

```bash
scp dist/shixpeer-ward-ubuntu.tar.gz root@BEACON_HOST:/root/.shixpeer.ward/bootstrap/
```

Далі **на Beacon під root**:

```bash
apt-get update
NEEDRESTART_MODE=l apt-get install --no-upgrade -y ca-certificates curl openssl acl
cd "$HOME/.shixpeer.ward/bootstrap"
tar -xzf shixpeer-ward-ubuntu.tar.gz
bash ubuntu/packaging/shixpeer-ward-install-beacon.sh --origin https://BEACON_HOST:8443
```

Якщо вікно needrestart уже відкрите, зніміть усі позначки пробілом, прокрутіть увесь список і підтвердьте порожній вибір. Режим `NEEDRESTART_MODE=l` лише виводить список служб; він не керує власними діями скриптів пакетів.

Встановлювач створює два непривілейовані облікові записи:

- `shixpeer-ward-beacon`: завантаження джерел, нормалізація і підпис; дані в
  `/home/shixpeer-ward-beacon/.shixpeer.ward/`.
- `shixpeer-ward-serve`: лише HTTPS-роздача опублікованих файлів; свій HOME і TLS-ключ.
  ACL дає йому читання public, але не ключа підпису, приватного CA або сирих кешів.

Створюються служба HTTPS і окремі oneshot-служба та таймер оновлення. Таймер
повторює синхронізацію через 6 годин після завершення попереднього проходу;
після reboot запускається знову. Перший імпорт стартує асинхронно і може
тривати помітний час. База не завантажується цілком у RAM; початковий кеш
у видавця істотно більший за базу агента. Не запускайте імпорт щохвилини.

Перевірити готовність:

```bash
journalctl -u shixpeer-ward-beacon-sync -f
```

Після успішного завершення вийдіть із перегляду Ctrl+C:

```bash
systemctl status shixpeer-ward-beacon --no-pager
systemctl status shixpeer-ward-beacon-sync --no-pager
systemctl list-timers shixpeer-ward-beacon-sync.timer
runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon /home/shixpeer-ward-beacon/.shixpeer.ward/bin/shixpeer-ward-beacon status
```

Служба sync після успіху може показувати `inactive (dead)` — це нормально для
oneshot; дивіться `Result=success` і наступний запуск таймера. Помилка імпорту
не затирає останню добру базу. Не можна обходити TTL старої бази.

Встановлювач не змінює фаєрвол. TCP 8443 має бути доступний агентам через ваші
наявні мережеві правила; обмежте його потрібними адресами. Не скидайте UFW
і не змінюйте SSH заради цього встановлення. HTTPS слухає IPv4/IPv6, якщо ОС це підтримує.

## Встановлення агента однією командою з Mac

Після першого успішного імпорту Beacon виконайте з кореня проєкту:

```bash
bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
```

Обидва SSH-хости мають бути заздалегідь перевірені й відомі OpenSSH; з'єднання
виконується під root без пересилання SSH-агента. Останній аргумент — адреса,
доступна із сервера агента і вказана в сертифікаті Beacon. Скрипт передає
через SSH лише публічний CA, публічний ключ підпису і встановлювач. Встановлювач
потім перевіряє підписаний реліз і завантажує бінарники через HTTPS. Закриті ключі
Beacon лишаються на Beacon. Ручний варіант нижче потрібен, якщо з Mac немає SSH-доступу
до обох серверів.

## 3. Початкова довіра для агентів — один раз

Не завантажуйте CA з невідомого сервера і не використовуйте `curl -k`.
Потрібні публічний CA і **два незалежно отримані відбитки** з консолі Beacon:
публічного ключа підпису (SPKI SHA256) і самого install.sh (SHA256).
Відбиток встановлювача захищає навіть від підміни скрипта скомпрометованим
процесом HTTPS; однієї перевірки підпису бінарника всередині підміненого скрипта замало.

Повторно вивести відбитки на довіреному Beacon:

```bash
runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon /home/shixpeer-ward-beacon/.shixpeer.ward/bin/shixpeer-ward-beacon release -state /home/shixpeer-ward-beacon/.shixpeer.ward/beacon -binaries /home/shixpeer-ward-beacon/.shixpeer.ward/releases -signing-key /home/shixpeer-ward-beacon/.shixpeer.ward/pki/signing.key -release-ttl 720h
```

CA — публічний сертифікат, не приватний ключ. Підготуйте його в HOME вашого
SSH-користувача на Beacon, без надання доступу до закритих ключів:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
runuser -u shixpeer-ward-beacon -- cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/ca.crt > "$HOME/.shixpeer.ward/bootstrap/beacon-ca.crt"
```

На кожному сервері агента один раз підготуйте каталог і передайте цей файл через
автентифікований SSH, перевіривши host key Beacon:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
scp root@BEACON_HOST:/root/.shixpeer.ward/bootstrap/beacon-ca.crt "$HOME/.shixpeer.ward/bootstrap/ca.crt"
```

`ca.key`, `signing.key`, `server.key` агентам не передавати. Якщо використовуєте свій
сертифікат публічного CA замість створеного приватного, локальний файл CA і
`--cacert`/`--ca-file` не потрібні, але незалежні відбитки все одно потрібні.

## 4. Встановлення агента: дві команди після підготовки довіри

Замініть `BEACON_HOST`, `INSTALLER_SHA256` і `FEED_KEY_SHA256` довіреними
значеннями з попередніх кроків. Типово створюється окремий мінімальний
користувач `shixpeer-ward-agent`, служба і його домашній каталог:

```bash
curl --fail --show-error --proto '=https' --tlsv1.2 --noproxy '*' --user-agent Shixpeer-Ward-Installer/1 --cacert "$HOME/.shixpeer.ward/bootstrap/ca.crt" https://BEACON_HOST:8443/install.sh -o "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" && printf '%s  %s\n' 'INSTALLER_SHA256' "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" | sha256sum -c -
```

```bash
bash "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" --beacon https://BEACON_HOST:8443 --ca-file "$HOME/.shixpeer.ward/bootstrap/ca.crt" --key-sha256 FEED_KEY_SHA256
```

Другу команду запускайте **лише після успішної перевірки першої**. Встановлювач
перевіряє Ed25519-підпис релізу, строк дії, розмір і
SHA256 бінарників, потім створює налаштування і службу systemd. Завантажуються обидві
Linux-збірки однаковими запитами в усіх клієнтів, вибір архітектури локальний. Відбиток, конфлікт
релізу або відкат до старішого релізу призводять до відмови. Мережевого redirect на
інший URL не виконується. Нічого не додається в групу docker, і в
роботі демона немає sudo. Якщо `--user` пропущено, створюється мінімальний непривілейований
`shixpeer-ward-agent` з HOME `/home/shixpeer-ward-agent`. Приклад із `--user "$USER"` — явний вибір
вашого поточного непривілейованого користувача, якщо вам це потрібно; додаткових груп
встановлювач не видає. Не змінюйте користувача між встановленням і повторними
запусками: у кожного облікового запису окремі база і checkpoint.

Бінарник автоматично не оновлюється: повторне встановлення запускає адміністратор
з актуальним відбитком скрипта. Оновлення бази йде окремо й автоматично.

## 5. Перший звіт на Ubuntu

Для стандартного встановлення з окремим `shixpeer-ward-agent`:

```bash
systemctl status shixpeer-ward-agent --no-pager
journalctl -u shixpeer-ward-agent -n 50 --no-pager
runuser -u shixpeer-ward-agent -- tail -f /home/shixpeer-ward-agent/.shixpeer.ward/logs/agent.log
```

На старті служба спершу намагається синхронізувати базу, потім створює перший
звіт. Далі маніфест бази перевіряється раз на хвилину, звіт — щогодини. Помилки
проходу журналюються, процес лишається живим. Журнал звітів обмежено двома файлами по 4 МіБ. Ctrl+C припиняє перегляд журналу,
а не службу.

Для явного тесту в консолі:

```bash
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent update
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent scan
```

Консоль покаже охоплення, збіги за пріоритетом, сумнівні записи і попередження.
Повні файли:

```bash
less /home/shixpeer-ward-agent/.shixpeer.ward/agent/report.md
```

JSON: `/home/shixpeer-ward-agent/.shixpeer.ward/agent/report.json`. У ньому є вихідні
версії, джерело, умови, порівнювана версія і рекомендації.
Якщо ви явно обрали `--user "$USER"`, використовуйте свій HOME без sudo:

```bash
"$HOME/.shixpeer.ward/bin/shixpeer-ward-agent" update
"$HOME/.shixpeer.ward/bin/shixpeer-ward-agent" scan
less "$HOME/.shixpeer.ward/agent/report.md"
```

Команди встановлення виконуються під root. Під час входу під root не додавайте `--user "$USER"`: встановлювач сам створює `shixpeer-ward-agent`. Не змішуйте root і звичайний HOME. За потреби окремого ручного
привілейованого аудиту налаштуйте root-агент окремо через `sudo -H`: дані
будуть у `/root/.shixpeer.ward/`. Це явне рішення адміністратора, не поведінка
встановлювача. Без root деякі PID, служби і контейнери лишаться недоступними.

## 6. Змінити джерела й інтервали

Джерела на Beacon: `/home/shixpeer-ward-beacon/.shixpeer.ward/config/beacon.json`.
Список уже містить типові джерела Ubuntu, Debian, macOS, NVD, CVE/GHSA,
KEV/EPSS і підтримуваних мовних екосистем. Можна вимикати й додавати
підтримувані адаптери; не можна підміняти довільний JSON непідтримуваним форматом.
Відсутнє джерело не означає відсутності вразливостей.

Оновити зараз:

```bash
systemctl start shixpeer-ward-beacon-sync.service
```

Інтервали змінюйте через перевизначення systemd; після правки unit або override виконайте
`systemctl daemon-reload` і перезапустіть потрібну службу чи таймер. Прапорці агента:
`run -feed-interval 1m -collect-interval 1h`. Бінарники, ключі і конфіг не видаляйте
під час очищення бази: checkpoint захищає від відкату. Не публікуйте звіти агентів
через Beacon — він роздає лише дозволені публічні артефакти.

## 7. Перенести старе локальне встановлення

Перед зміною розташування зупиніть старого агента, якщо він запущений. З новим
бінарником, **від попереднього користувача**:

```bash
bin/shixpeer-ward-agent migrate-home
```

За нестандартного розташування:

```bash
bin/shixpeer-ward-agent migrate-home -from-config /absolute/path/to/old/agent.json
```

Команда копіює налаштування, публічний CA, базу, checkpoint і звіти в новий HOME.
Старі файли зберігаються як резервна копія; після перевірки нового встановлення їх
можна видалити або перемістити вручну. Повторна міграція не перезаписує наявну
довіру. Посилання на старий CA замінюється домашньою копією. Прострочена база лишається
простроченою — після міграції потрібен `update`, а не обхід перевірки часу.

## Діагностика

- `snapshot HTTPS request failed`: перевірте робочий Beacon, адресу і порт,
  доступність із мережі агента, відповідність DNS або IP сертифікату і довірений CA.
- 404 manifest: перший імпорт ще не завершився або завершився помилкою.
- Прострочена база: виправте імпорт, мережу або годинник, потім update. Не вимикайте підпис і TTL.
- Багато NOT_CHECKED: дивіться причини, права і покриття; це не список безпечного програмного забезпечення.
- Контейнери не видно: немає доступу до локального сокета Docker. Встановлювач навмисно
  не видає фактично root-права через групу docker.
- Служба не запускається: `journalctl -u ІМ'Я -n 100 --no-pager`.

Архів релізу і встановлювачі перевіряються локально; встановлення на ваших справжніх
серверах виконуєте ви. Див. також [покриття сканера](scanning.md),
[межі довіри](trust.md), [офіційну документацію OpenSSL](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/)
і [systemd sandbox](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

Після помилки синхронізації агент повторює спробу протягом хвилини або через
коротший налаштований інтервал. Фонове оновлення зі зміненими файлами бази одразу запитує
новий звіт. Незмінений маніфест або подовження строку публікації без зміни
файлів позапланове сканування не запускають. Сканування послідовні, одночасних процесів, що пишуть звіт, немає.
Після зміни налаштувань агента через setup перезапустіть його службу: конфігурація
читається під час старту і не змінюється віддалено під час роботи.

## Якщо Beacon уже встановлено зі старими іменами

Для нового встановлення цей крок не потрібен. Для наявного встановлення заплануйте
коротку перерву в HTTPS-роздачі. Зробіть резервну копію домашніх каталогів
служб, включно з ключами і базою. Під root зупиніть лише служби Ward:

```bash
systemctl stop shixpeer-ward-beacon-sync.timer shixpeer-ward-beacon-sync.service shixpeer-ward-beacon.service
```

Якщо нових облікових записів і домашніх каталогів ще немає, перейменуйте старі,
зберігаючи UID, GID і ACL:

```bash
usermod -l shixpeer-ward-beacon -d /home/shixpeer-ward-beacon -m ward-beacon
groupmod -n shixpeer-ward-beacon ward-beacon
usermod -l shixpeer-ward-serve -d /home/shixpeer-ward-serve -m ward-serve
groupmod -n shixpeer-ward-serve ward-serve
```

Потім запустіть новий встановлювач Beacon із тим самим `--origin`. Він оновить
файли unit і ACL та використає перенесені ключі. Якщо старі й нові
облікові записи вже існують одночасно, не об'єднуйте каталоги наосліп.

Для агента, встановленого під старим виділеним користувачем, зупиніть
`shixpeer-ward-agent.service`, перейменуйте обліковий запис так само
(`ward-agent` → `shixpeer-ward-agent`, HOME → `/home/shixpeer-ward-agent`),
потім повторіть встановлення з перевіреним новим скриптом і тим самим ключем видавця.
Встановлювач оновить конфігурацію шляхів; каталог бази і checkpoint лишаються
в перенесеному HOME. Агентам, встановленим під явно обраним користувачем,
перейменування не потрібне.

Для наявного встановлення див. [оновлення без скидання ключів і бази](ubuntu-update.uk.md).
