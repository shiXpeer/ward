# Ubuntu: Beacon, установка агента и первый отчёт

Для Ubuntu 24.04/systemd, amd64 или arm64. Команды ниже запускает администратор;
разработка на Mac не означает, что что-то уже установлено на ваших серверах.
Проект: https://shixpeer.com. Go на серверах не нужен: используются готовые бинарники.

## Быстрый путь с Mac

Готовый архив лежит в `dist/shixpeer-ward-ubuntu.tar.gz` (пересобрать:
`make ubuntu-bundle`). Для нового Beacon с установленным `acl`:

```bash
bash packaging/shixpeer-ward-deploy-beacon.sh BEACON_SSH_HOST https://BEACON_HOST:8443
```

Если Beacon уже установлен, этот шаг пропусти. После первой успешной публикации
выполни одну команду на каждый сервер агента:

```bash
bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
```

Оба SSH-хоста принимают необязательный порт: например,
`beacon.example.org:2222` и `agent.example.org:2200`. Без порта применяются
настройки OpenSSH. HTTPS-адрес в последнем аргументе задаётся отдельно.

Используй SSH-ключи и заранее проверенные записи обоих хостов в known_hosts.
На агенте нужны curl и OpenSSL. Скрипты не меняют SSH и firewall. Ниже приведён
ручной вариант для диагностики и случаев, когда прямого SSH-доступа нет.

## Что именно проверяется

Агент локально собирает установленные dpkg-пакеты и версии исходных пакетов,
ОС, ядро, сервисы, слушающие TCP/UDP-сокеты и доступных владельцев процессов,
метаданные запущенных Docker-контейнеров и их опубликованные порты, глобальные
npm/Python-пакеты. Поддерживаемые правила сверяются с подписанной локальной базой.
Ничего из инвентаризации на Beacon не отправляется. Все агенты получают общую базу.

Для работающего ядра Ubuntu используется `/proc/version_signature`, для Debian —
поддерживаемая сигнатура сборки `uname -v`. Для подписанных Ubuntu-образов исходный
пакет берётся из Built-Using. Версия установленного пакета не подставляется вместо
версии загруженного ядра. Если связать их нельзя, будет UNRESOLVED/NOT_CHECKED.
Сигнал `/var/run/reboot-required` и известное отставание загруженной версии
показываются как предупреждение: после обновления может требоваться reboot.

Это частичный сканер. Неизвестные продукты, сложные условия CVE, пакеты внутри
контейнеров, проектные lockfile/venv и неподдерживаемые схемы версий остаются явно
непроверенными. Порт нельзя «обновить»: отчёт показывает привязку и владельца,
а внешняя доступность зависит от firewall/NAT/облачных правил.
Если ss/iproute2 отсутствует, читаются таблицы /proc/net, без атрибуции владельцев. Проверки извне нет.
Совпадение версионного правила — основание проверить advisory и обновление,
а не доказательство успешной эксплуатации. Автообновления ОС/ПО, reboot,
правок UFW/firewall/SSH и docker exec нет.

## Где лежат данные

По умолчанию всё состояние Ward находится в HOME **пользователя процесса**:

```text
~/.shixpeer.ward/
  bin/                      установленные бинарники и служебные скрипты
  config/agent.json         адрес Beacon, публичный ключ, каталог данных
  config/ca.crt             доверенный публичный CA, если используется частный HTTPS
  agent/database/           подписанная локальная база и checkpoint от отката
  agent/snapshot.json       локальный снимок
  agent/report.md           читаемый отчёт
  agent/report.json         полный отчёт и доказательства
  beacon/                   состояние/кеш/публичная база издателя (на Beacon)
  pki/                      ключи только на соответствующем сервере/пользователе
  releases/                 Linux-бинарники для раздачи (на Beacon)
  logs/agent.log            журнал отчётов демона, до 4 MiB + предыдущий файл
```

Обычный запуск — HOME текущего пользователя; `sudo -H` — `/root`. Демон работает
не от root. При `--user ubuntu` это `/home/ubuntu/.shixpeer.ward/`; при созданном
установщиком `shixpeer-ward-agent` — `/home/shixpeer-ward-agent/.shixpeer.ward/`. Базы/отчёты не лежат
в checkout, `/var/lib` или рядом с исходниками. systemd-unit файлы естественно
устанавливаются в `/etc/systemd/system`; journal запуска/ошибок службы хранится самим systemd; мини-отчёты демона
пишутся в домашний logs/agent.log, а не в journal.
Флаги `-state`, `-config`, `-report-dir` остаются явными расширенными переопределениями.

## 1. Собрать архив на Mac/машине разработки

В корне репозитория:

```bash
make check
make ubuntu-bundle
```

Получится `dist/shixpeer-ward-ubuntu.tar.gz`: оба приложения для Linux amd64/arm64,
настройки источников и установщик Beacon. `dist/` исключён из репозитория.
Это dev-сборка; не выдавайте её за опубликованный стабильный релиз.

## 2. Подготовить отдельный сервер Beacon

В примерах `BEACON_HOST` — ваш реальный DNS или IPv4. Для частной сети удобно
использовать стабильный внутренний адрес; TLS-сертификат создаётся именно для него.
Установщик использует порт 8443. Никакого публичного официального Ward endpoint
по умолчанию не существует.

На Beacon создайте каталог для архива:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
```

С Mac передайте архив по SSH с проверенным host key:

```bash
scp dist/shixpeer-ward-ubuntu.tar.gz root@BEACON_HOST:/root/.shixpeer.ward/bootstrap/
```

Далее **на Beacon под root**:

```bash
apt-get update
NEEDRESTART_MODE=l apt-get install --no-upgrade -y ca-certificates curl openssl acl
cd "$HOME/.shixpeer.ward/bootstrap"
tar -xzf shixpeer-ward-ubuntu.tar.gz
bash ubuntu/packaging/shixpeer-ward-install-beacon.sh --origin https://BEACON_HOST:8443
```

Если уже открыто окно needrestart, снимите все галочки пробелом, прокрутите весь список и подтвердите пустой выбор. Режим `NEEDRESTART_MODE=l` только выводит список служб; он не управляет собственными действиями скриптов пакетов.

Установщик создаёт два непривилегированных аккаунта:

- `shixpeer-ward-beacon`: загрузка источников, нормализация и подпись; данные в
  `/home/shixpeer-ward-beacon/.shixpeer.ward/`.
- `shixpeer-ward-serve`: только HTTPS-раздача опубликованных файлов; свой HOME и TLS-ключ.
  ACL даёт ему чтение public, но не ключа подписи, приватного CA или сырых кешей.

Создаются служба HTTPS и отдельные oneshot-служба/таймер обновления. Таймер
повторяет синхронизацию через 6 часов после завершения предыдущего прохода;
после reboot запускается снова. Первый импорт запускается асинхронно и может
занять заметное время. База не загружается целиком в RAM; первоначальный кеш
на издателе существенно больше агентской базы. Не запускать импорт каждую минуту.

Проверить готовность:

```bash
journalctl -u shixpeer-ward-beacon-sync -f
```

После успешного завершения выйти из просмотра Ctrl+C:

```bash
systemctl status shixpeer-ward-beacon --no-pager
systemctl status shixpeer-ward-beacon-sync --no-pager
systemctl list-timers shixpeer-ward-beacon-sync.timer
runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon /home/shixpeer-ward-beacon/.shixpeer.ward/bin/shixpeer-ward-beacon status
```

Служба sync после успеха может показывать `inactive (dead)` — это нормально для
oneshot; смотрите `Result=success` и следующий запуск таймера. Ошибка импорта
не затирает последнюю хорошую базу. Нельзя обходить TTL старой базы.

Установщик не меняет firewall. TCP 8443 должен быть доступен агентам через ваши
существующие сетевые правила; ограничьте его нужными адресами. Не сбрасывайте UFW
и не меняйте SSH ради этой установки. HTTPS слушает IPv4/IPv6 при поддержке ОС.

## Установка агента одной командой с Mac

После первого успешного импорта Beacon выполни из корня проекта:

```bash
bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
```

Оба SSH-хоста должны быть заранее проверены и известны OpenSSH; подключение
выполняется под root без пересылки SSH-агента. Последний аргумент — адрес,
доступный с сервера агента и указанный в сертификате Beacon. Скрипт передаёт
через SSH только публичный CA, публичный ключ подписи и установщик. Установщик
затем проверяет подписанный релиз и скачивает бинарники по HTTPS. Закрытые ключи
Beacon остаются на Beacon. Ручной вариант ниже нужен, если с Mac нет SSH-доступа
к обоим серверам.

## 3. Первичное доверие для агентов — один раз

Не скачивайте CA с неизвестного сервера и не используйте `curl -k`.
Нужны публичный CA и **два независимо полученных отпечатка** из консоли Beacon:
публичного ключа подписи (SPKI SHA256) и самого install.sh (SHA256).
Отпечаток установщика защищает даже от подмены скрипта скомпрометированным
HTTPS-процессом; одной проверки подписи бинарника внутри подменённого скрипта мало.

Повторно вывести отпечатки на доверенном Beacon:

```bash
runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon /home/shixpeer-ward-beacon/.shixpeer.ward/bin/shixpeer-ward-beacon release -state /home/shixpeer-ward-beacon/.shixpeer.ward/beacon -binaries /home/shixpeer-ward-beacon/.shixpeer.ward/releases -signing-key /home/shixpeer-ward-beacon/.shixpeer.ward/pki/signing.key -release-ttl 720h
```

CA — публичный сертификат, не приватный ключ. Подготовьте его в HOME вашего
SSH-пользователя на Beacon (без выдачи доступа к закрытым ключам):

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
runuser -u shixpeer-ward-beacon -- cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/ca.crt > "$HOME/.shixpeer.ward/bootstrap/beacon-ca.crt"
```

На каждом сервере-агенте один раз подготовьте каталог и передайте этот файл по
аутентифицированному SSH, проверив host key Beacon:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
scp root@BEACON_HOST:/root/.shixpeer.ward/bootstrap/beacon-ca.crt "$HOME/.shixpeer.ward/bootstrap/ca.crt"
```

`ca.key`, `signing.key`, `server.key` агентам не передавать. Если используете свой
сертификат публичного CA вместо созданного частного, локальный CA-файл и
`--cacert`/`--ca-file` не нужны, но независимые отпечатки всё равно нужны.

## 4. Установка агента — две команды после подготовки доверия

Замените `BEACON_HOST`, `INSTALLER_SHA256` и `FEED_KEY_SHA256` доверенными
значениями из предыдущих шагов. По умолчанию создаётся отдельный минимальный
пользователь `shixpeer-ward-agent`, служба и его домашний каталог:

```bash
curl --fail --show-error --proto '=https' --tlsv1.2 --noproxy '*' --user-agent Shixpeer-Ward-Installer/1 --cacert "$HOME/.shixpeer.ward/bootstrap/ca.crt" https://BEACON_HOST:8443/install.sh -o "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" && printf '%s  %s\n' 'INSTALLER_SHA256' "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" | sha256sum -c -
```

```bash
bash "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" --beacon https://BEACON_HOST:8443 --ca-file "$HOME/.shixpeer.ward/bootstrap/ca.crt" --key-sha256 FEED_KEY_SHA256
```

Вторую команду запускайте **только после успешной проверки первой**. Установщик
проверяет Ed25519-подпись релиза, срок действия, размер и
SHA256 бинарников, затем создаёт настройки и systemd-службу. Скачиваются обе
Linux-сборки одинаковыми запросами у всех клиентов, выбор архитектуры локальный. Отпечаток, конфликт
релиза или откат к более старому релизу приводят к отказу. Сетевой redirect на
другой URL не выполняется. Ничего не добавляется в группу docker и нет sudo в
работе демона. Если `--user` опущен, создаётся минимальный непривилегированный
`shixpeer-ward-agent` с HOME `/home/shixpeer-ward-agent`. Пример с `--user "$USER"` — явный выбор
вашего текущего непривилегированного пользователя, если вам это нужно; дополнительные группы
установщик не выдаёт. Не меняйте пользователя между установкой и повторными
запусками: у каждой учётной записи отдельная база и checkpoint.

Бинарник автоматически не обновляется: повторную установку запускает администратор
с актуальным отпечатком скрипта. Обновление базы идёт отдельно и автоматически.

## 5. Первый отчёт на Ubuntu

Для стандартной установки с отдельным `shixpeer-ward-agent`:

```bash
systemctl status shixpeer-ward-agent --no-pager
journalctl -u shixpeer-ward-agent -n 50 --no-pager
runuser -u shixpeer-ward-agent -- tail -f /home/shixpeer-ward-agent/.shixpeer.ward/logs/agent.log
```

На старте служба сначала пытается синхронизировать базу, потом создаёт первый
отчёт. В дальнейшем манифест базы проверяется раз в минуту, отчёт — каждый час. Ошибки
прохода журналируются, процесс остаётся жив. Журнал отчётов ограничен двумя файлами по 4 MiB. Ctrl+C прекращает просмотр журнала,
а не службу.

Для явного теста в консоли:

```bash
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent update
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent scan
```

Консоль покажет охват, совпадения по приоритету, сомнительные записи и предупреждения.
Полные файлы:

```bash
less /home/shixpeer-ward-agent/.shixpeer.ward/agent/report.md
```

JSON: `/home/shixpeer-ward-agent/.shixpeer.ward/agent/report.json`. В нём есть исходные
версии, источник, условия, сравниваемая версия и рекомендации.
Если вы явно выбрали `--user "$USER"`, используйте свой HOME без sudo:

```bash
"$HOME/.shixpeer.ward/bin/shixpeer-ward-agent" update
"$HOME/.shixpeer.ward/bin/shixpeer-ward-agent" scan
less "$HOME/.shixpeer.ward/agent/report.md"
```

Команды установки выполняются под root. При входе под root не добавляйте `--user "$USER"`: установщик сам создаёт `shixpeer-ward-agent`. Не смешивайте root и обычный HOME. При необходимости отдельного ручного
привилегированного аудита настройте root-агент отдельно под `sudo -H`: данные
будут в `/root/.shixpeer.ward/`. Это явное решение администратора, не поведение
установщика. Без root некоторые PID/сервисы/контейнеры останутся недоступными.

## 6. Изменить источники и интервалы

Источники на Beacon: `/home/shixpeer-ward-beacon/.shixpeer.ward/config/beacon.json`.
Список уже содержит дефолтные источники Ubuntu, Debian, macOS, NVD, CVE/GHSA,
KEV/EPSS и поддерживаемых языковых экосистем. Можно отключать/добавлять
поддерживаемые адаптеры; нельзя подменять произвольный JSON неподдерживаемым форматом.
Отсутствующий источник не означает отсутствия уязвимостей.

Обновить сейчас:

```bash
systemctl start shixpeer-ward-beacon-sync.service
```

Менять интервалы через systemd overrides; после правки unit/override выполнить
`systemctl daemon-reload` и перезапустить нужную службу/таймер. Флаги агента:
`run -feed-interval 1m -collect-interval 1h`. Бинарники, ключи и конфиг не удалять
при очистке базы: checkpoint защищает от отката. Не публиковать отчёты агентов
через Beacon — он раздаёт только разрешённые публичные артефакты.

## 7. Перенести старую локальную установку

Перед сменой расположения остановите старый агент, если он запущен. С новым
бинарником, **от прежнего пользователя**:

```bash
bin/shixpeer-ward-agent migrate-home
```

При нестандартном расположении:

```bash
bin/shixpeer-ward-agent migrate-home -from-config /absolute/path/to/old/agent.json
```

Команда копирует настройки, публичный CA, базу, checkpoint и отчёты в новый HOME.
Старые файлы сохраняются как резервная копия; после проверки новой установки их
можно удалить/переместить вручную. Повторная миграция не перезаписывает существующее
доверие. Ссылка на старый CA заменяется домашней копией. Истёкшая база остаётся
истёкшей — после миграции нужен `update`, а не обход проверки времени.

## Диагностика

- `snapshot HTTPS request failed`: проверьте работающий Beacon, адрес/порт,
  доступность из сети агента, соответствие DNS/IP сертификату и доверенный CA.
- 404 manifest: первый импорт ещё не завершён или завершился ошибкой.
- Просрочена база: исправить импорт/сеть/часы, затем update. Не выключать подпись/TTL.
- Много NOT_CHECKED: смотреть причины, права и покрытие; это не список безопасного ПО.
- Контейнеры не видны: нет доступа к локальному Docker socket. Установщик намеренно
  не выдаёт фактически root-права через группу docker.
- Служба не запускается: `journalctl -u ИМЯ -n 100 --no-pager`.

Архив релиза и установщики проверяются локально; установка на ваших реальных
серверах выполняется вами. См. также [покрытие сканера](scanning.md),
[границы доверия](trust.md), [официальную документацию OpenSSL](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/)
и [systemd sandbox](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

При ошибке синхронизации агент повторяет попытку в течение минуты (либо через
более короткий настроенный интервал). Фоновое обновление с изменёнными файлами базы сразу запрашивает
новый отчёт. Неизменившийся манифест или продление срока публикации без изменения
файлов внеплановый скан не запускают. Сканирования последовательны, конкурирующих писателей отчёта нет.
После смены настроек агента через setup перезапустите его службу: конфигурация
читается при старте, а не изменяется удалённо во время работы.

## Если Beacon уже установлен со старыми именами

Для новой установки этот шаг не нужен. Для существующей установки запланируйте
короткий перерыв в HTTPS-раздаче. Сделайте резервную копию домашних каталогов
служб, включая ключи и базу. Под root остановите только службы Ward:

```bash
systemctl stop shixpeer-ward-beacon-sync.timer shixpeer-ward-beacon-sync.service shixpeer-ward-beacon.service
```

Если новых аккаунтов и домашних каталогов ещё нет, переименуйте старые,
сохраняя UID/GID и ACL:

```bash
usermod -l shixpeer-ward-beacon -d /home/shixpeer-ward-beacon -m ward-beacon
groupmod -n shixpeer-ward-beacon ward-beacon
usermod -l shixpeer-ward-serve -d /home/shixpeer-ward-serve -m ward-serve
groupmod -n shixpeer-ward-serve ward-serve
```

Затем запустите новый установщик Beacon с прежним `--origin`. Он обновит
unit-файлы и ACL и использует перенесённые ключи. Если старые и новые
аккаунты уже существуют одновременно, не объединяйте каталоги вслепую.

Для агента, установленного под старым выделенным пользователем, остановите
`shixpeer-ward-agent.service`, переименуйте аккаунт аналогично
(`ward-agent` → `shixpeer-ward-agent`, HOME → `/home/shixpeer-ward-agent`),
затем повторите установку с проверенным новым скриптом и тем же ключом издателя.
Установщик обновит конфигурацию путей; каталог базы и checkpoint остаются
в перенесённом HOME. Агентам, установленным под явно выбранным пользователем,
переименование не требуется.

Для существующей установки см. [обновление без сброса ключей и базы](ubuntu-update.ru.md).
