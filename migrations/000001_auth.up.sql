-- Authentication: accounts, roles and their grants, unit module access, security policy, sessions, password
-- resets, the audit log and the token signing keys. Masters (role, app_user) have the standard columns first, as
-- every master table of ALIR; the rest are operational tables. Every instant is timestamptz (UTC sessions).
-- Organisation scope codes are Portal Master unit codes: no foreign key across services.
CREATE SCHEMA IF NOT EXISTS auth;

CREATE FUNCTION auth.uuid_v7() RETURNS uuid
    LANGUAGE plpgsql VOLATILE AS
$$
DECLARE
    u  bytea := uuid_send(gen_random_uuid());
    ms bytea := substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3);
BEGIN
    u := overlay(u PLACING ms FROM 1 FOR 6);
    u := set_byte(u, 6, (get_byte(u, 6) & 15) | 112);
    RETURN encode(u, 'hex')::uuid;
END
$$;

CREATE TABLE auth.code_prefix (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,
    name                    varchar(150) NOT NULL,
    description             varchar(500) NULL,

    -- Status
    is_active               boolean      NOT NULL DEFAULT true,
    is_deleted              boolean      NOT NULL DEFAULT false,

    -- Workflow (state: where the record is in its approval; status: approved, void, cancelled, posted, …)
    state                   varchar(20)  NULL,
    status                  varchar(20)  NULL,
    remark                  varchar(500) NULL,
    approval_level_required integer      NULL,
    approved_at             timestamptz  NULL,
    approved_by             uuid         NULL,

    -- Validity
    valid_from              date         NULL,
    valid_to                date         NULL,

    -- Audit
    created_at              timestamptz  NOT NULL DEFAULT now(),
    created_by              uuid         NOT NULL,
    updated_at              timestamptz  NULL,
    updated_by              uuid         NULL,
    deleted_at              timestamptz  NULL,
    deleted_by              uuid         NULL,
    version                 integer      NOT NULL DEFAULT 1,
    prefix                  varchar(10)  NOT NULL,
    digits                  smallint     NOT NULL DEFAULT 3,
    last_number             bigint       NOT NULL DEFAULT 0,
    CONSTRAINT code_prefix_pkey PRIMARY KEY (id),
    CONSTRAINT code_prefix_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT code_prefix_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT code_prefix_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT code_prefix_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT code_prefix_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    ),
    CONSTRAINT code_prefix_prefix_check CHECK (prefix ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT code_prefix_digits_check CHECK (digits BETWEEN 1 AND 9),
    CONSTRAINT code_prefix_last_number_check CHECK (last_number >= 0)
);
CREATE UNIQUE INDEX code_prefix_code_ci ON auth.code_prefix (lower(code));

-- ---------------------------------------------------------------- Peran (role); grants per menu
CREATE TABLE auth.role (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,
    name                    varchar(150) NOT NULL,
    description             varchar(500) NULL,

    -- Status
    is_active               boolean      NOT NULL DEFAULT true,
    is_deleted              boolean      NOT NULL DEFAULT false,

    -- Workflow (state: where the record is in its approval; status: approved, void, cancelled, posted, …)
    state                   varchar(20)  NULL,
    status                  varchar(20)  NULL,
    remark                  varchar(500) NULL,
    approval_level_required integer      NULL,
    approved_at             timestamptz  NULL,
    approved_by             uuid         NULL,

    -- Validity
    valid_from              date         NULL,
    valid_to                date         NULL,

    -- Audit
    created_at              timestamptz  NOT NULL DEFAULT now(),
    created_by              uuid         NOT NULL,
    updated_at              timestamptz  NULL,
    updated_by              uuid         NULL,
    deleted_at              timestamptz  NULL,
    deleted_by              uuid         NULL,
    version                 integer      NOT NULL DEFAULT 1,
    -- Role Attributes
    is_system               boolean      NOT NULL DEFAULT false, -- built in: never deactivated or deleted

    CONSTRAINT role_pkey PRIMARY KEY (id),
    CONSTRAINT role_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT role_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT role_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT role_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT role_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    )
);
CREATE UNIQUE INDEX role_code_ci ON auth.role (lower(code));
CREATE INDEX idx_role_active ON auth.role (is_active, is_deleted);

CREATE TABLE auth.role_grant (
    role_id                 uuid         NOT NULL,
    menu                    varchar(60)  NOT NULL,  -- catalog menu id, e.g. pm.orgUnit
    actions                 text[]       NOT NULL,
    CONSTRAINT role_grant_pkey PRIMARY KEY (role_id, menu),
    CONSTRAINT role_grant_role_fk FOREIGN KEY (role_id) REFERENCES auth.role (id) ON DELETE CASCADE,
    CONSTRAINT role_grant_actions_check CHECK (cardinality(actions) > 0)
);

-- ---------------------------------------------------------------- Pengguna (account); name = full name
CREATE TABLE auth.app_user (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,
    name                    varchar(150) NOT NULL,
    description             varchar(500) NULL,

    -- Status
    is_active               boolean      NOT NULL DEFAULT true,
    is_deleted              boolean      NOT NULL DEFAULT false,

    -- Workflow (state: where the record is in its approval; status: approved, void, cancelled, posted, …)
    state                   varchar(20)  NULL,
    status                  varchar(20)  NULL,
    remark                  varchar(500) NULL,
    approval_level_required integer      NULL,
    approved_at             timestamptz  NULL,
    approved_by             uuid         NULL,

    -- Validity
    valid_from              date         NULL,
    valid_to                date         NULL,

    -- Audit
    created_at              timestamptz  NOT NULL DEFAULT now(),
    created_by              uuid         NOT NULL,
    updated_at              timestamptz  NULL,
    updated_by              uuid         NULL,
    deleted_at              timestamptz  NULL,
    deleted_by              uuid         NULL,
    version                 integer      NOT NULL DEFAULT 1,
    -- Account Attributes
    username                varchar(60)  NOT NULL,
    password_hash           text         NULL,      -- argon2id; NULL for SSO-only accounts
    role_id                 uuid         NOT NULL,
    level_code              varchar(20)  NULL,      -- GROUP | REGION | WILAYAH | COMPANY | OPERATIONAL_UNIT | ORG_LEVEL_1..3
    ownership_code          varchar(10)  NULL,
    -- Organisation scope: Portal Master unit codes, from the top down to the level
    owner_code              varchar(40)  NULL,
    group_code              varchar(40)  NULL,
    region_code             varchar(40)  NULL,
    wilayah_code            varchar(40)  NULL,
    gmk_code                varchar(40)  NULL,
    company_code            varchar(40)  NULL,
    operational_unit_code   varchar(40)  NULL,
    org_level1_code         varchar(40)  NULL,
    org_level2_code         varchar(40)  NULL,
    org_level3_code         varchar(40)  NULL,
    identity_issuer         varchar(200) NULL,
    external_subject        varchar(200) NULL,
    -- Sign-in state
    failed_logins           integer      NOT NULL DEFAULT 0,
    locked_until            timestamptz  NULL,
    must_change_password    varchar(10)  NULL,      -- first | expired | reset
    password_changed_at     timestamptz  NULL,
    last_login_at           timestamptz  NULL,

    CONSTRAINT app_user_pkey PRIMARY KEY (id),
    CONSTRAINT app_user_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT app_user_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT app_user_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT app_user_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT app_user_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    ),
    CONSTRAINT app_user_username_check CHECK (username ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT app_user_role_fk FOREIGN KEY (role_id) REFERENCES auth.role (id),
    CONSTRAINT app_user_level_check CHECK (level_code IS NULL OR level_code IN ('OWNER', 'GROUP', 'REGION', 'WILAYAH', 'GMK', 'COMPANY', 'OPERATIONAL_UNIT', 'ORG_LEVEL_1', 'ORG_LEVEL_2', 'ORG_LEVEL_3')),
    CONSTRAINT app_user_must_change_check CHECK (must_change_password IS NULL OR must_change_password IN ('first', 'expired', 'reset')),
    CONSTRAINT app_user_failed_check CHECK (failed_logins >= 0)
);
CREATE UNIQUE INDEX app_user_code_ci ON auth.app_user (lower(code));
CREATE UNIQUE INDEX app_user_username_live ON auth.app_user (username) WHERE NOT is_deleted;
CREATE UNIQUE INDEX app_user_external_live ON auth.app_user (identity_issuer, external_subject) WHERE NOT is_deleted AND external_subject IS NOT NULL;
CREATE INDEX idx_app_user_active ON auth.app_user (is_active, is_deleted);
CREATE INDEX idx_app_user_role ON auth.app_user (role_id);
CREATE INDEX idx_app_user_unit ON auth.app_user (operational_unit_code);

CREATE TABLE auth.password_history (
    user_id                 uuid         NOT NULL,
    password_hash           text         NOT NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT password_history_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE CASCADE
);
CREATE INDEX idx_password_history_user ON auth.password_history (user_id, created_at DESC);

-- ---------------------------------------------------------------- Akses Modul Unit
-- Modules an operational unit may use; no row = every module.
CREATE TABLE auth.unit_access (
    unit_code               varchar(40)  NOT NULL,
    all_modules             boolean      NOT NULL,
    modules                 text[]       NOT NULL DEFAULT '{}',
    updated_at              timestamptz  NOT NULL DEFAULT now(),
    updated_by              uuid         NULL,
    CONSTRAINT unit_access_pkey PRIMARY KEY (unit_code),
    CONSTRAINT unit_access_modules_check CHECK (all_modules OR cardinality(modules) > 0)
);

-- ---------------------------------------------------------------- Kebijakan keamanan (one row)
CREATE TABLE auth.security_policy (
    id                         smallint     NOT NULL DEFAULT 1,
    password_min_length        integer      NOT NULL DEFAULT 8,
    require_uppercase          boolean      NOT NULL DEFAULT false,
    require_number             boolean      NOT NULL DEFAULT true,
    require_symbol             boolean      NOT NULL DEFAULT false,
    password_expiry_days       integer      NOT NULL DEFAULT 0,
    password_history           integer      NOT NULL DEFAULT 0,
    max_failed_attempts        integer      NOT NULL DEFAULT 5,
    lockout_minutes            integer      NOT NULL DEFAULT 15,
    session_hours              integer      NOT NULL DEFAULT 8,
    idle_minutes               integer      NOT NULL DEFAULT 0,
    allow_concurrent_sessions  boolean      NOT NULL DEFAULT true,
    allow_local_login          boolean      NOT NULL DEFAULT true,
    sso_enabled                boolean      NOT NULL DEFAULT false,
    sso_issuer                 varchar(200) NULL,
    sso_client_id              varchar(200) NULL,
    updated_at                 timestamptz  NULL,
    updated_by                 uuid         NULL,
    CONSTRAINT security_policy_pkey PRIMARY KEY (id),
    CONSTRAINT security_policy_one_row CHECK (id = 1),
    CONSTRAINT security_policy_values_check CHECK (
        password_min_length BETWEEN 6 AND 128 AND password_expiry_days BETWEEN 0 AND 3650 AND password_history BETWEEN 0 AND 24
        AND max_failed_attempts BETWEEN 0 AND 100 AND lockout_minutes BETWEEN 1 AND 1440 AND session_hours BETWEEN 1 AND 720
        AND idle_minutes BETWEEN 0 AND 1440)
);
INSERT INTO auth.security_policy (id) VALUES (1);

-- ---------------------------------------------------------------- Sessions and password resets
-- A session is one sign-in: a rotating refresh token (stored as its SHA-256), short access tokens signed for it.
CREATE TABLE auth.session (
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),
    user_id                 uuid         NOT NULL,
    refresh_hash            bytea        NOT NULL,
    previous_hash           bytea        NULL,      -- the refresh token it replaced: shown again = stolen, end the session
    method                  varchar(10)  NOT NULL DEFAULT 'local',
    ip                      varchar(64)  NULL,
    user_agent              varchar(300) NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    last_seen_at            timestamptz  NOT NULL DEFAULT now(),
    expires_at              timestamptz  NOT NULL,
    revoked_at              timestamptz  NULL,
    CONSTRAINT session_pkey PRIMARY KEY (id),
    CONSTRAINT session_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX session_refresh ON auth.session (refresh_hash);
CREATE INDEX idx_session_previous ON auth.session (previous_hash) WHERE previous_hash IS NOT NULL;
CREATE INDEX idx_session_user_live ON auth.session (user_id) WHERE revoked_at IS NULL;

CREATE TABLE auth.password_reset (
    token_hash              bytea        NOT NULL,
    user_id                 uuid         NOT NULL,
    expires_at              timestamptz  NOT NULL,
    used_at                 timestamptz  NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT password_reset_pkey PRIMARY KEY (token_hash),
    CONSTRAINT password_reset_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------- Audit log
CREATE TABLE auth.audit_event (
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),
    at                      timestamptz  NOT NULL DEFAULT now(),
    type                    varchar(30)  NOT NULL,
    actor_id                uuid         NULL,
    actor_username          varchar(60)  NULL,
    actor_name              varchar(150) NULL,
    target                  varchar(200) NULL,
    ip                      varchar(64)  NULL,
    detail                  varchar(500) NULL,
    request_id              varchar(64)  NULL,
    CONSTRAINT audit_event_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_audit_event_at ON auth.audit_event (at DESC);
CREATE INDEX idx_audit_event_type ON auth.audit_event (type, at DESC);

-- ---------------------------------------------------------------- Token signing keys (Ed25519)
CREATE TABLE auth.signing_key (
    kid                     varchar(40)  NOT NULL,
    private_key             bytea        NOT NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    retired_at              timestamptz  NULL,
    CONSTRAINT signing_key_pkey PRIMARY KEY (kid)
);

-- ---------------------------------------------------------------- Built-in roles and generated codes
INSERT INTO auth.role (code, name, description, is_system, created_by) VALUES
    ('admin',     'Admin',     'Semua menu, termasuk pengguna dan koneksi', true, '00000000-0000-7000-8000-000000000000'),
    ('analyst',   'Analyst',   'Analisis, dataset, report, template',       true, '00000000-0000-7000-8000-000000000000'),
    ('publisher', 'Publisher', 'Menyetujui dan menayangkan halaman Publish', true, '00000000-0000-7000-8000-000000000000'),
    ('viewer',    'Viewer',    'Melihat dashboard dan analisis',            true, '00000000-0000-7000-8000-000000000000');

INSERT INTO auth.code_prefix (code, name, description, prefix, digits, created_by) VALUES
    ('role',     'Peran',    'Kode peran baru: MRL001, …',     'MRL', 3, '00000000-0000-7000-8000-000000000000'),
    ('app_user', 'Pengguna', 'Kode pengguna baru: MUS0001, …', 'MUS', 4, '00000000-0000-7000-8000-000000000000');
