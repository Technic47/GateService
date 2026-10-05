# Gate Service

Единая точка входа для сервисов домашнего сервера. Разворачивается на VPS и проверяет
авторизацию **до** того, как запрос уйдёт в reverse SSH-туннель — неавторизованный трафик
до домашнего сервера не долетает.

Заменяет `auth_basic` в Nginx на `auth_request` с нормальной регистрацией, ролями
и разграничением доступа по сервисам.

---

## Состояние сборки

Версия **0.2.0** (Gate Auth), развёрнута на VPS 05.10.2026. Стек соответствует CLAUDE.md: **Java 25 + Spring Boot 4.1**.
`mvn clean package` собирает `target/gate-service-0.2.0.jar`; `mvn test` — 64 теста, из них интеграционные на
PostgreSQL 16 в Testcontainers (нужен локальный Docker, см. «Gate Auth» ниже).

| | |
|---|---|
| **JDK** | Oracle GraalVM 25+37-LTS (`~/.jdks/graalvm-jdk-25`), `release 25` |
| **Spring Boot** | 4.1.1 — последний GA ветки 4.1 на 15.09.2026 |
| **Spring Framework** | 7.0.9 |
| **Spring Security** | 7.1.1 |
| **Hibernate ORM** | 7.4.5.Final |
| **Thymeleaf** | 3.1.5.RELEASE (`thymeleaf-spring6` — так артефакт называется и под Framework 7) |
| **Flyway** | 12.4.0 |
| **PostgreSQL JDBC** | 42.7.13 |
| **gate-auth-core** | 0.1.0 (Maven Central, `io.github.technic47.gateauth`) — подпись токенов Gate Auth |

На 4.2 переходить пока рано: доступен только `4.2.0-M1`, это milestone, не GA.
Проверить, не вышел ли новый патч 4.1:

```bash
mvn versions:display-parent-updates -DallowMinorUpdates=false -DallowMajorUpdates=false
```

**Проверено на живой БД** (PostgreSQL 16 в Docker, профиль `dev`):

- Flyway применяет `V1__init.sql` и `V2__common_auth.sql`, `ddl-auto=validate` проходит — схема миграций совпадает с сущностями
- Все страницы отдают 200, включая `/admin/setup` (там record-аксессоры через SpEL)
- Thymeleaf подставляет CSRF в формы, вход и выход работают
- `/verify`: 200 на разрешённый сервис, 403 на неизвестный, 403 без заголовка, 401 анонимно
- Пользователь с одним доступным сервисом с `/portal` редиректится прямо в сервис; `?choose=1` показывает список
- USER на `/admin/**` получает 403
- События пишутся в `activity_log` с причинами отказов

Работа за реальным Nginx с `auth_request` проверена на VPS (15.09.2026, Gate Auth — 05.10.2026).
Чего всё ещё не проверял: native-образ.

---

## Что умеет

| | |
|---|---|
| **Вход и регистрация** | Одна страница с двумя вкладками, bcrypt, «запомнить меня» |
| **Портал сервисов** | Плитки доступных сервисов. **Один доступный сервис — экран пропускается**, пользователь попадает прямо в него |
| **`/verify` для Nginx** | `auth_request`: 200 / 401 / 403 по cookie сессии и заголовку `X-Service-Name` |
| **Журнал активности** | Входы, отказы, действия админов. Фильтры по пользователю, типу, сервису, датам. Те же события — строкой в stdout |
| **Админка: пользователи** | CRUD, блокировка, сброс пароля, одобрение, выдача доступа к сервисам |
| **Админка: сервисы** | CRUD, `host`/`port` upstream-а, публичный URL, проверка доступности порта |
| **Админка: настройки гейта** | Политика регистрации, защита входа, сессии, срок хранения журнала, режим обслуживания, состояние репликации PostgreSQL, генератор конфига Nginx |

### Роли

- `ADMIN` — админка целиком, по умолчанию доступ ко всем сервисам (отключается галочкой в настройках)
- `USER` — только выданные сервисы

---

## Быстрый старт

### 1. База данных

Postgres уже поднят (`pg-primary` на 144.31.187.7). Нужны база и роль для приложения:

```sql
CREATE ROLE gate LOGIN PASSWORD 'пароль_из_.env';
CREATE DATABASE gate OWNER gate;

-- Чтобы страница настроек показывала состояние репликации.
-- Без этого гейт работает, но таблица реплик будет пустой.
GRANT pg_monitor TO gate;
```

Схему создаст Flyway при первом старте (`src/main/resources/db/migration/`).

### 2. Переменные окружения

```bash
cp .env.example .env
```

Заполнить обязательно:

- `GATE_DB_PASSWORD` — пароль роли `gate`
- `GATE_REMEMBER_ME_KEY` — `openssl rand -base64 32`, **менять нельзя** после первой выдачи токенов
- `GATE_ADMIN_PASSWORD` — если оставить пустым, при первом старте сгенерируется случайный
  и **один раз** напечатается в лог

### 3. Запуск

**Локально** — с локальной БД, `.env` не нужен:

```bash
docker compose -f docker-compose.dev.yml up -d
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

Дальше http://localhost:9000, вход `admin` / `admin12345` (дефолты профиля `dev`).

⚠️ **К primary на VPS с домашней машины не подключиться.** Порт 5432 отвечает, но
`pg_hba.conf` пускает только standby (`2.26.60.167`) и только для репликации:

```
FATAL: no pg_hba.conf entry for host "...", user "gate", database "gate"
```

Добавлять домашний IP в `pg_hba.conf` не стоит — он динамический, и это открыло бы
аутентификацию Postgres в интернет. Если primary нужен именно живой — SSH-туннель:

```bash
ssh -L 5433:localhost:5432 user@144.31.187.7
GATE_DB_HOST=localhost GATE_DB_PORT=5433 mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

**На VPS:**

```bash
docker compose up -d --build
```

Профиль `dev` отличается тремя вещами: локальная БД с дефолтными кредами, гейт слушает
все интерфейсы, cookie разрешена по HTTP. В прод его тащить нельзя.

### 4. Nginx

Готовый конфиг под текущий список сервисов генерируется на странице
**Настройки гейта** — с уже подставленными именами в `X-Service-Name`.
Скопировать оттуда, а не писать руками: расхождение имени в заголовке и в БД даёт
403 «неизвестный сервис», и ищется такая опечатка долго.

Общая форма:

```nginx
location = /_gate_verify {
    internal;
    proxy_pass http://127.0.0.1:9000/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Service-Name "fashionmark";
    proxy_set_header X-Original-URI $request_uri;
}

location / {
    auth_request /_gate_verify;
    error_page 401 = @gate_login;    # не вошёл  → на форму входа
    error_page 403 = @gate_denied;   # вошёл, но доступа нет → на страницу отказа
    proxy_pass https://127.0.0.1:8080;
}
```

**401 и 403 обязаны вести в разные места.** Если оба уводят на логин, пользователь без
доступа попадёт в бесконечный редирект: он уже аутентифицирован, логин отправляет его
обратно в сервис, сервис снова отвечает 403.

**Сам гейт генератор не описывает** — ему нужен отдельный `server` на 443. На VPS это
`/etc/nginx/sites-enabled/default`:

```nginx
# 80 — только редирект: по http гейт не работает, cookie у него Secure
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl default_server;       # default_server обязателен, см. ниже
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate     /etc/nginx/certs/home-access.crt;
    ssl_certificate_key /etc/nginx/certs/home-access.key;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        # $remote_addr, а не $proxy_add_x_forwarded_for: гейт берёт первый адрес цепочки,
        # а его клиент может подставить сам
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

На 443 живёт ещё сайт `vpn` (`vpn.kuz-net-dom.ru`). При заходе по голому IP браузер
не шлёт SNI, и Nginx отдаёт запрос серверу по умолчанию — без `default_server` у гейта
им оказывается `vpn`, который на любой путь отвечает `OK`.

На что уже наступали при переключении:

- **Upstream сервиса — туннель (`127.0.0.1:8080`), а не старый `:8843`.** Гейт трафик
  не проксирует, upstream нужен только проверке доступности и генератору.
- **`location /` в блоке сервиса проксирует в туннель, а не в гейт.** Если туда попадёт
  `proxy_pass http://127.0.0.1:9000`, на `:8843` откроется второй экземпляр портала,
  и «переход в сервис» будет бесконечно возвращать на него же.
- **Ключевые строки не править в редакторе поверх старого файла**, а перезаписывать файл
  целиком: закомментированный `# listen 443 ssl default_server;` рядом с раскомментированным
  IPv6-вариантом отдаёт гейт только по IPv6, и это не видно ни в `nginx -t`, ни глазами.

---

## Gate Auth: токены для приложений

Гейт подписывает для приложений токены по общему стандарту (`../gate-auth`, спецификация —
`docs/gate-auth-spec-v1.md`): `X-Gate-Assertion` на каждый разрешённый `/verify`, публичный ключ на
`/.well-known/jwks.json`, вход из локальной сети через `/auth/handoff`. Ключ — `GATE_SIGNING_KEY`
(см. `.env.example`); без него всё работает по-старому. Подробности и порядок выката — в `CLAUDE.md`,
раздел «Gate Auth».

Зависимость `gate-auth-core` берётся из Maven Central. `mvn test` поднимает PostgreSQL в Testcontainers —
нужен локальный Docker, а активный context обычно `vps-germany`. Поэтому так:

```bash
DOCKER_HOST=npipe:////./pipe/dockerDesktopLinuxEngine mvn test      # Git Bash
```

Ключ подписи — `GATE_SIGNING_KEY` в локальном `.env`, **в одинарных кавычках**: `GATE_SIGNING_KEY='{"kty":"OKP",…}'`.
Сгенерировать (PowerShell, Java 25):

```powershell
& "$env:USERPROFILE\.jdks\graalvm-jdk-25\bin\java.exe" -cp "$env:USERPROFILE\.m2\repository\io\github\technic47\gateauth\gate-auth-core\0.1.0\gate-auth-core-0.1.0.jar" io.github.technic47.gateauth.core.KeyTool
```

После смены ключа: `docker compose up -d --force-recreate gate`, в логе — `ключ подписи загружен, kid=…`.

## Два адреса у сервиса

У сущности `ProtectedService` два адреса, и путать их — самая вероятная ошибка настройки:

- **`host` + `port`** — upstream, куда Nginx проксирует **после** разрешения.
  Для FashionMark это `127.0.0.1:8080`, локальный конец SSH-туннеля. Отсюда же
  берётся проверка доступности порта и генерация конфига.
- **`publicUrl`** — куда гейт отправляет **браузер** после входа, например
  `https://144.31.187.7:8843`. Плитка в портале ведёт сюда.

До upstream браузер не достучится: `127.0.0.1` на VPS — это сам VPS. Если `publicUrl`
не задан, гейт подставит upstream и переход из портала работать не будет.

---

## Почему схема работает без домена

Cookie не различают порты. Сессия, выставленная гейтом на `144.31.187.7`, уезжает
и на `144.31.187.7:8843`. Именно на этом всё держится — и именно это не умели
Authelia и Tinyauth, которым нужен домен с точкой для валидации cookie.

Обратная сторона: **cookie обязана быть `Secure`**, то есть и гейт, и сервисы —
только за HTTPS. По HTTP сессия уйдёт открытым текстом, и её подберёт кто угодно
на пути. `GATE_COOKIE_SECURE=false` существует исключительно для локальной отладки.

---

## Логирование

Каждое событие пишется в два места:

1. **Таблица `activity_log`** — источник для `/admin/activity` с фильтрами и историей.
2. **Логгер `gate.activity`** — одна строка в stdout:
   ```
   LOGIN_FAILURE user=petya service=- ip=203.0.113.9 ok=false Неверный логин или пароль
   ```
   Это то, что видно в `docker logs` и в **Dozzle**.

Dozzle поднимается тем же `docker-compose.yml` на `127.0.0.1:9001`. Он показывает
stdout контейнеров — логи Postgres, Nginx и самого гейта, включая то, что случилось
до того, как запись в БД стала возможна. Срез по пользователям и отказам он не даёт,
это задача `/admin/activity`.

Собственную авторизацию Dozzle не включает намеренно: заведите его как сервис `dozzle`
с upstream `127.0.0.1:9001` на странице `/admin/services` — и логи закроются той же
авторизацией, что и всё остальное. Заодно это наглядная проверка, что гейт работает.

`/verify` дёргается Nginx на **каждый** запрос, включая статику. Поэтому разрешённые
проверки по умолчанию не журналируются — галочка «писать разрешённые проверки» в настройках
нужна только на время разбора конкретной проблемы. Отказы пишутся всегда.

---

## Известные ограничения

- **Сессии живут в памяти процесса.** Перезапуск разлогинивает всех, у кого не отмечено
  «запомнить меня». Лечится внешним хранилищем сессий, которое для десятка пользователей избыточно.
- **`rememberMeDays` применяется после перезапуска** — срок жизни токена задаётся при сборке
  цепочки фильтров Spring Security. Остальные настройки действуют сразу.
- **Настройки кешируются в памяти** одного экземпляра. При нескольких экземплярах гейта они
  разъедутся; гейт разворачивается в одном.
- **`/verify` ходит в БД на каждый запрос.** Осознанный размен: отзыв доступа и блокировка
  действуют мгновенно, а не после перелогина. При десятке пользователей и запросе
  по уникальному индексу нагрузка пренебрежима.
- **Native image не проверялся.** Обращения к бинам из шаблонов (`${@fmt.dateTime(...)}`)
  идут через SpEL-рефлексию — это первое место, где стоит искать проблемы.
  Собирать на машине с 8+ ГБ RAM, не на VPS.
- **Репликация PostgreSQL идёт без TLS** между двумя хостерами по открытому интернету
  (унаследовано из текущей инфраструктуры, см. CLAUDE.md). Страница настроек про это
  напоминает. Гейт этого не чинит.

---

## Структура

```
src/main/java/com/technic/gate/
├── domain/      сущности: User, ProtectedService, UserServiceRole, ActivityLog, GateSetting + enum-ы
├── repo/        Spring Data репозитории
├── security/    SecurityConfig, UserDetails, обработчики входа/выхода, лок по попыткам
├── service/     AccessVerifier (решение о доступе), ActivityService (журнал),
│                UserAdminService, ServiceCatalogService, GateSettingsService,
│                HealthProbe, NginxConfigGenerator, DatabaseStatusService,
│                GateTokenService (Gate Auth: подпись токенов, JWKS)
├── web/         AuthController, PortalController, VerifyController,
│                HandoffController, JwksController + admin/
└── config/      DataSeeder, ActivityRetentionJob

src/main/resources/
├── templates/   layout.html (фрагменты) + страницы
├── static/css/  app.css
└── db/migration/V1__init.sql, V2__common_auth.sql
```

`thymeleaf-layout-dialect` не используется — тянет Groovy и несовместим с native-image
(CLAUDE.md). Переиспользование разметки — на штатных `th:fragment` / `th:replace`.

---

## Сборка

Отдельный Maven в PATH не установлен, wrapper не сгенерирован. Рабочий вариант без
доустановки чего-либо — Maven, встроенный в IntelliJ (именно им проверялась компиляция):

```bash
export JAVA_HOME="/c/Users/Techn/.jdks/graalvm-jdk-25"
export PATH="$JAVA_HOME/bin:$PATH"
MVN="/c/Program Files/JetBrains/IntelliJ IDEA 2025.3/plugins/maven/lib/maven3/bin/mvn"

"$MVN" -B clean package
```

Чтобы не набирать путь каждый раз, имеет смысл один раз сгенерировать wrapper
(нужна сеть) — дальше проект собирается через `./mvnw`:

```bash
"$MVN" -N wrapper:wrapper -Dmaven=3.9.9
```

### Native image

В `~/.jdks/graalvm-jdk-25` уже есть `native-image`, так что локальная сборка возможна:

```bash
export JAVA_HOME="/c/Users/Techn/.jdks/graalvm-jdk-25"
"$MVN" -Pnative native:compile -DskipTests
```

⚠️ **На Windows для этого дополнительно нужен MSVC** — GraalVM использует системный
линкер. Потребуется «Visual Studio Build Tools» с рабочей нагрузкой *Desktop development
with C++*, и запускать сборку из «x64 Native Tools Command Prompt». Без этого
`native-image` падает на этапе линковки.

Проще не возиться и собрать в Docker — базовые образы проверены, теги существуют:

```bash
docker build -f Dockerfile.native -t gate-service:native .
```

В обоих случаях собирать на рабочей машине, не на VPS: native-image требует 8+ ГБ RAM,
которых там нет. Готовый бинарник — `target/gate-service`.

---

## Порты

Занято на primary VPS: 43615, 48157 (AmneziaWG), 8443 (Hysteria2), 8080 (SSH-туннель,
только loopback), 3000, 3001 (AdGuard / Tinyauth), 5432 (pg-primary), 8844 (панель 3x-ui через Nginx).

Nginx на VPS: **80** → редирект на https, **443** → гейт (`default_server`; по SNI
`vpn.kuz-net-dom.ru` — сайт `vpn`), **8843** → FashionMark через `auth_request`.

Занимается этим проектом: **9000** (гейт), **9001** (Dozzle) — оба **только на `127.0.0.1`**.
Гейт запущен в `network_mode: host` и слушает `127.0.0.1` сам (`GATE_BIND_ADDRESS`),
Dozzle — в bridge с публикацией на `127.0.0.1`. Перед деплоем всё равно проверьте `ss -tulnp`.

Порт гейта не должен быть доступен из интернета: доверие к `X-Forwarded-For` держится
ровно на том, что снаружи до него не достучаться.
