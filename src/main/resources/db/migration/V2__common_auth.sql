-- Общий стандарт авторизации Gate Auth v1 (../gate-auth/docs/gate-auth-spec-v1.md).

-- Настройки сервиса для приложений, которые подключили библиотеку gate-auth.
--  direct_enabled — разрешён ли вход из LAN через /auth/handoff (direct mode, §6 спецификации);
--  redirect_uris  — куда гейту разрешено отправлять ответ handoff, по одному адресу на строку.
--                   Сравнение строго побайтовое: ни префиксов, ни шаблонов;
--  api_prefix     — путь API приложения: для него сгенерированный конфиг Nginx отвечает
--                   401/403 JSON-ом вместо редиректа на форму входа. Пусто — без отдельного блока.
ALTER TABLE services ADD COLUMN direct_enabled boolean       NOT NULL DEFAULT false;
ALTER TABLE services ADD COLUMN redirect_uris  varchar(2048);
ALTER TABLE services ADD COLUMN api_prefix     varchar(128);

-- Роль пользователя внутри конкретного приложения (claim "roles" в токене).
-- Отдельной таблицей, а не колонкой в user_service_access: та таблица — @ManyToMany в JPA,
-- и Hibernate вправе пересоздать её строки целиком, потеряв лишнюю колонку.
-- Строка живёт только пока выдан доступ: при отзыве доступа роль удаляется вместе с ним.
CREATE TABLE user_service_role (
    user_id    bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    service_id bigint      NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    role       varchar(32) NOT NULL,
    PRIMARY KEY (user_id, service_id)
);

CREATE INDEX idx_service_role_service ON user_service_role (service_id);
