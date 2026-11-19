-- Multi-tenant identity (Stage 1A). One installation serves many companies (tenants). A person signs in once with
-- one global identity (email or username + password) and works in each company they are a member of:
--
--   tenant          a company using ALIR (its code is its address, e.g. gan.alir.example)
--   identity        the person: global, one password, one lockout, optional email (unique), platform-admin flag
--   identity_link   a federated identity of the person (issuer + subject: AD, Google, …; connectors come later)
--   membership      the person in one tenant: username there, role, organisation scope, employee, kind
--                   (workforce = employee/admin of the company, external = vendor/public applicant)
--
-- Roles, grants, unit access, the security policy, generated codes, sessions, the audit log and mail belong to a
-- tenant. Every row that exists now belongs to the first tenant, "Grup Agro Nusantara". Ids are kept: the identity
-- and the membership of a migrated account both take the old account id, so created_by/updated_by/audit actor ids
-- (the person) and the frontend's /users/:id (the membership) stay valid.
-- Authentication is the one service that crosses tenants (sign-in by email looks at every company), so tenants are
-- kept apart by the queries (tenant_id in every lookup), not by Row-Level Security as in Portal Master.

-- ---------------------------------------------------------------- Tenant
CREATE TABLE auth.tenant (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,      -- address of the company: lower case, digits, -
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

    CONSTRAINT tenant_pkey PRIMARY KEY (id),
    CONSTRAINT tenant_code_check CHECK (code ~ '^[a-z0-9][a-z0-9-]*$'),
    CONSTRAINT tenant_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT tenant_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT tenant_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT tenant_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    )
);
CREATE UNIQUE INDEX tenant_code_ci ON auth.tenant (lower(code));

INSERT INTO auth.tenant (id, code, name, description, created_by) VALUES
    ('00000000-0000-7000-8000-0000000000a1', 'gan', 'Grup Agro Nusantara', 'Perusahaan pertama (data sebelum multi-tenant)',
     '00000000-0000-7000-8000-000000000000');

-- ---------------------------------------------------------------- Identity (global person)
CREATE TABLE auth.identity (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,
    name                    varchar(150) NOT NULL,
    description             varchar(500) NULL,

    -- Status
    is_active               boolean      NOT NULL DEFAULT true,  -- false: the person cannot sign in anywhere
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
    -- Identity Attributes
    email                   varchar(254) NULL,       -- sign-in email (lower case); unique among live identities
    email_verified_at       timestamptz  NULL,
    password_hash           text         NULL,       -- argon2id; NULL: signs in only through an identity provider
    is_platform_admin       boolean      NOT NULL DEFAULT false, -- manages tenants (not the data of a tenant)
    -- Sign-in state
    failed_logins           integer      NOT NULL DEFAULT 0,
    locked_until            timestamptz  NULL,
    must_change_password    varchar(10)  NULL,       -- first | expired | reset
    password_changed_at     timestamptz  NULL,
    last_login_at           timestamptz  NULL,

    CONSTRAINT identity_pkey PRIMARY KEY (id),
    CONSTRAINT identity_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT identity_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT identity_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT identity_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT identity_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    ),
    CONSTRAINT identity_email_check CHECK (email IS NULL OR (email = lower(email) AND email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$')),
    CONSTRAINT identity_must_change_check CHECK (must_change_password IS NULL OR must_change_password IN ('first', 'expired', 'reset')),
    CONSTRAINT identity_failed_check CHECK (failed_logins >= 0)
);
CREATE UNIQUE INDEX identity_code_ci ON auth.identity (lower(code));
CREATE UNIQUE INDEX identity_email_live ON auth.identity (email) WHERE NOT is_deleted AND email IS NOT NULL;

-- ---------------------------------------------------------------- Identity link (federated identities)
CREATE TABLE auth.identity_link (
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),
    identity_id             uuid         NOT NULL,
    issuer                  varchar(200) NOT NULL,
    subject                 varchar(200) NOT NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    created_by              uuid         NOT NULL,
    CONSTRAINT identity_link_pkey PRIMARY KEY (id),
    CONSTRAINT identity_link_identity_fk FOREIGN KEY (identity_id) REFERENCES auth.identity (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX identity_link_subject ON auth.identity_link (issuer, subject);
CREATE INDEX idx_identity_link_identity ON auth.identity_link (identity_id);

-- ---------------------------------------------------------------- Membership (the person in one tenant)
CREATE TABLE auth.membership (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,
    name                    varchar(150) NOT NULL,      -- name in this tenant (the employee's when linked)
    description             varchar(500) NULL,

    -- Status
    is_active               boolean      NOT NULL DEFAULT true,  -- false: no sign-in to this tenant
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
    -- Membership Attributes
    tenant_id               uuid         NOT NULL,
    identity_id             uuid         NOT NULL,
    kind                    varchar(10)  NOT NULL DEFAULT 'workforce', -- workforce | external
    username                varchar(60)  NOT NULL,      -- unique in the tenant
    role_id                 uuid         NOT NULL,
    level_code              varchar(20)  NULL,
    ownership_code          varchar(10)  NULL,
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
    employee_id             uuid         NULL,          -- Portal Master Karyawan of this tenant (no FK across services)
    employee_code           varchar(40)  NULL,
    last_login_at           timestamptz  NULL,

    CONSTRAINT membership_pkey PRIMARY KEY (id),
    CONSTRAINT membership_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT membership_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT membership_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT membership_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT membership_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    ),
    CONSTRAINT membership_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id),
    CONSTRAINT membership_identity_fk FOREIGN KEY (identity_id) REFERENCES auth.identity (id),
    CONSTRAINT membership_role_fk FOREIGN KEY (role_id) REFERENCES auth.role (id),
    CONSTRAINT membership_kind_check CHECK (kind IN ('workforce', 'external')),
    CONSTRAINT membership_username_check CHECK (username ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT membership_level_check CHECK (level_code IS NULL OR level_code IN ('OWNER', 'GROUP', 'REGION', 'WILAYAH', 'GMK', 'COMPANY', 'OPERATIONAL_UNIT', 'ORG_LEVEL_1', 'ORG_LEVEL_2', 'ORG_LEVEL_3')),
    CONSTRAINT membership_employee_pair CHECK ((employee_id IS NULL) = (employee_code IS NULL))
);
CREATE UNIQUE INDEX membership_code_ci ON auth.membership (tenant_id, lower(code));
CREATE UNIQUE INDEX membership_username_live ON auth.membership (tenant_id, username) WHERE NOT is_deleted;
CREATE UNIQUE INDEX membership_identity_live ON auth.membership (tenant_id, identity_id) WHERE NOT is_deleted;
CREATE UNIQUE INDEX membership_employee_live ON auth.membership (tenant_id, employee_id) WHERE NOT is_deleted AND employee_id IS NOT NULL;
CREATE INDEX idx_membership_identity ON auth.membership (identity_id) WHERE NOT is_deleted;
CREATE INDEX idx_membership_username ON auth.membership (username) WHERE NOT is_deleted;
CREATE INDEX idx_membership_role ON auth.membership (role_id);

-- ---------------------------------------------------------------- Tenant-owned setup
ALTER TABLE auth.role ADD COLUMN tenant_id uuid NULL;
UPDATE auth.role SET tenant_id = '00000000-0000-7000-8000-0000000000a1';
ALTER TABLE auth.role ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT role_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id);
DROP INDEX auth.role_code_ci;
CREATE UNIQUE INDEX role_code_ci ON auth.role (tenant_id, lower(code));

ALTER TABLE auth.code_prefix ADD COLUMN tenant_id uuid NULL;
UPDATE auth.code_prefix SET tenant_id = '00000000-0000-7000-8000-0000000000a1';
ALTER TABLE auth.code_prefix ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT code_prefix_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id);
DROP INDEX auth.code_prefix_code_ci;
CREATE UNIQUE INDEX code_prefix_code_ci ON auth.code_prefix (tenant_id, lower(code));

ALTER TABLE auth.unit_access ADD COLUMN tenant_id uuid NULL;
UPDATE auth.unit_access SET tenant_id = '00000000-0000-7000-8000-0000000000a1';
ALTER TABLE auth.unit_access ALTER COLUMN tenant_id SET NOT NULL, DROP CONSTRAINT unit_access_pkey,
    ADD CONSTRAINT unit_access_pkey PRIMARY KEY (tenant_id, unit_code),
    ADD CONSTRAINT unit_access_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id);

ALTER TABLE auth.security_policy ADD COLUMN tenant_id uuid NULL;
UPDATE auth.security_policy SET tenant_id = '00000000-0000-7000-8000-0000000000a1';
ALTER TABLE auth.security_policy DROP CONSTRAINT security_policy_one_row, DROP CONSTRAINT security_policy_pkey,
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT security_policy_pkey PRIMARY KEY (tenant_id),
    ADD CONSTRAINT security_policy_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id);
ALTER TABLE auth.security_policy DROP COLUMN id;

-- ---------------------------------------------------------------- Accounts → identities + memberships
INSERT INTO auth.identity (id, code, name, is_active, is_deleted, created_at, created_by, updated_at, updated_by, deleted_at, deleted_by,
    password_hash, is_platform_admin, failed_logins, locked_until, must_change_password, password_changed_at, last_login_at)
SELECT u.id, 'ID' || lpad(row_number() OVER (ORDER BY u.created_at, u.id)::text, 6, '0'), u.name, true, u.is_deleted, u.created_at,
    u.created_by, u.updated_at, u.updated_by, u.deleted_at, u.deleted_by, u.password_hash,
    -- the first administrator (made by the service) manages the tenants of the installation
    (u.code = 'MUS0000' AND NOT u.is_deleted), u.failed_logins, u.locked_until, u.must_change_password, u.password_changed_at, u.last_login_at
FROM auth.app_user u;

INSERT INTO auth.identity_link (identity_id, issuer, subject, created_by)
SELECT u.id, u.identity_issuer, u.external_subject, coalesce(u.updated_by, u.created_by)
FROM auth.app_user u WHERE u.external_subject IS NOT NULL AND NOT u.is_deleted;

INSERT INTO auth.membership (id, code, name, description, is_active, is_deleted, valid_from, valid_to, created_at, created_by, updated_at,
    updated_by, deleted_at, deleted_by, version, tenant_id, identity_id, kind, username, role_id, level_code, ownership_code, owner_code,
    group_code, region_code, wilayah_code, gmk_code, company_code, operational_unit_code, org_level1_code, org_level2_code,
    org_level3_code, employee_id, employee_code, last_login_at)
SELECT u.id, u.code, u.name, u.description, u.is_active, u.is_deleted, u.valid_from, u.valid_to, u.created_at, u.created_by, u.updated_at,
    u.updated_by, u.deleted_at, u.deleted_by, u.version, '00000000-0000-7000-8000-0000000000a1', u.id, 'workforce', u.username, u.role_id,
    u.level_code, u.ownership_code, u.owner_code, u.group_code, u.region_code, u.wilayah_code, u.gmk_code, u.company_code,
    u.operational_unit_code, u.org_level1_code, u.org_level2_code, u.org_level3_code, u.employee_id, u.employee_code, u.last_login_at
FROM auth.app_user u;

-- Identities are global: their code (ID000001, …) comes from one sequence of the installation, not a tenant's prefix.
CREATE SEQUENCE auth.identity_code_seq;
SELECT setval('auth.identity_code_seq', greatest((SELECT count(*) FROM auth.identity), 1), (SELECT count(*) FROM auth.identity) > 0);
ALTER TABLE auth.identity ALTER COLUMN code SET DEFAULT 'ID' || lpad(nextval('auth.identity_code_seq')::text, 6, '0');
UPDATE auth.code_prefix SET code = 'membership', name = 'Anggota', description = 'Kode anggota baru: MUS0001, …' WHERE code = 'app_user';

-- ---------------------------------------------------------------- Operational tables follow
ALTER TABLE auth.password_history DROP CONSTRAINT password_history_user_fk;
ALTER TABLE auth.password_history RENAME COLUMN user_id TO identity_id;
ALTER TABLE auth.password_history ADD CONSTRAINT password_history_identity_fk FOREIGN KEY (identity_id) REFERENCES auth.identity (id) ON DELETE CASCADE;

ALTER TABLE auth.password_reset DROP CONSTRAINT password_reset_user_fk;
ALTER TABLE auth.password_reset RENAME COLUMN user_id TO identity_id;
ALTER TABLE auth.password_reset ADD CONSTRAINT password_reset_identity_fk FOREIGN KEY (identity_id) REFERENCES auth.identity (id) ON DELETE CASCADE,
    ADD COLUMN tenant_id uuid NULL REFERENCES auth.tenant (id);       -- the company the link was made in (its policy applies)
UPDATE auth.password_reset SET tenant_id = '00000000-0000-7000-8000-0000000000a1';

-- A session is one sign-in of a person; it works in one membership at a time (switching company moves it).
ALTER TABLE auth.session DROP CONSTRAINT session_user_fk;
DROP INDEX auth.idx_session_user_live;
ALTER TABLE auth.session RENAME COLUMN user_id TO membership_id;
ALTER TABLE auth.session ADD COLUMN identity_id uuid NULL, ADD COLUMN tenant_id uuid NULL;
UPDATE auth.session SET identity_id = membership_id, tenant_id = '00000000-0000-7000-8000-0000000000a1';
ALTER TABLE auth.session ALTER COLUMN identity_id SET NOT NULL, ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT session_identity_fk FOREIGN KEY (identity_id) REFERENCES auth.identity (id) ON DELETE CASCADE,
    ADD CONSTRAINT session_membership_fk FOREIGN KEY (membership_id) REFERENCES auth.membership (id) ON DELETE CASCADE,
    ADD CONSTRAINT session_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id);
CREATE INDEX idx_session_identity_live ON auth.session (identity_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_session_membership_live ON auth.session (membership_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_session_tenant_live ON auth.session (tenant_id, last_seen_at DESC) WHERE revoked_at IS NULL;

ALTER TABLE auth.audit_event ADD COLUMN tenant_id uuid NULL;       -- NULL: an event of the installation (platform)
UPDATE auth.audit_event SET tenant_id = '00000000-0000-7000-8000-0000000000a1';
DROP INDEX auth.idx_audit_event_at;
DROP INDEX auth.idx_audit_event_type;
CREATE INDEX idx_audit_event_at ON auth.audit_event (tenant_id, at DESC);
CREATE INDEX idx_audit_event_type ON auth.audit_event (tenant_id, type, at DESC);

ALTER TABLE auth.mail_outbox DROP CONSTRAINT mail_outbox_user_fk;
ALTER TABLE auth.mail_outbox RENAME COLUMN user_id TO identity_id;
ALTER TABLE auth.mail_outbox ADD CONSTRAINT mail_outbox_identity_fk FOREIGN KEY (identity_id) REFERENCES auth.identity (id) ON DELETE SET NULL,
    ADD COLUMN tenant_id uuid NULL REFERENCES auth.tenant (id);
UPDATE auth.mail_outbox SET tenant_id = '00000000-0000-7000-8000-0000000000a1';

DROP TABLE auth.app_user;
