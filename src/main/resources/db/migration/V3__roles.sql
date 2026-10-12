-- Роли как справочник (Gate Auth §4.4–4.5, gate-auth 0.2.0): гейт — единственное место, где роли определяются.
-- Роль либо глобальная (service_id IS NULL: её можно выдать в любом приложении), либо роль одного приложения.
-- Выдаётся всегда в паре пользователь+приложение, и таких ролей у пары может быть несколько.
--  code       — то, что уходит в claim roles; не меняется после создания (приложения проверяют его в коде);
--  archived_at — вместо удаления: архивная роль не выдаётся и не попадает ни в токены, ни в каталог;
--               архивировать можно только роль, которая ни у кого не выдана.
CREATE TABLE roles (
    id          bigserial    PRIMARY KEY,
    code        varchar(32)  NOT NULL CHECK (code ~ '^[a-z][a-z0-9_-]{0,31}$'),
    name        varchar(100) NOT NULL,
    description varchar(500),
    service_id  bigint       REFERENCES services (id) ON DELETE CASCADE,
    sort_order  integer      NOT NULL DEFAULT 0,
    archived_at timestamptz,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_roles_global_code ON roles (code) WHERE service_id IS NULL;
CREATE UNIQUE INDEX uq_roles_service_code ON roles (service_id, code) WHERE service_id IS NOT NULL;
CREATE INDEX idx_roles_service ON roles (service_id);

-- Версия каталога ролей (claim rv): растёт при любом изменении определения роли. Одна строка.
CREATE TABLE role_catalog_version (
    id      integer PRIMARY KEY CHECK (id = 1),
    version bigint  NOT NULL
);
INSERT INTO role_catalog_version (id, version) VALUES (1, 1);

-- Существующие роли (0.2.0: одна строка-роль на пару пользователь+приложение) становятся ролями этих приложений.
INSERT INTO roles (code, name, service_id)
SELECT DISTINCT r.role, r.role, r.service_id
FROM user_service_role r;

-- user_service_role: вместо текста роли — ссылка на роль, несколько ролей на пару.
ALTER TABLE user_service_role ADD COLUMN role_id bigint REFERENCES roles (id) ON DELETE CASCADE;
UPDATE user_service_role u
SET role_id = r.id
FROM roles r
WHERE r.service_id = u.service_id
  AND r.code = u.role;
ALTER TABLE user_service_role ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE user_service_role DROP CONSTRAINT user_service_role_pkey;
ALTER TABLE user_service_role DROP COLUMN role;
ALTER TABLE user_service_role ADD PRIMARY KEY (user_id, service_id, role_id);
CREATE INDEX idx_user_service_role_role ON user_service_role (role_id);
