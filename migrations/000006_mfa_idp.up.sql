-- Multi-factor authentication (TOTP + recovery codes) and the Identity Provider master (Stage 1D).
--
-- MFA belongs to the person (identity), like the password: one authenticator for every company. Each company's
-- policy says off | optional | required; required and not enrolled = the session grants nothing until enrolled.
-- Secrets are sealed with AES-256-GCM (AUTH_SECRET_KEY), bound to their row.

ALTER TABLE auth.security_policy
    ADD COLUMN mfa_mode varchar(10) NOT NULL DEFAULT 'optional',
    ADD CONSTRAINT security_policy_mfa_check CHECK (mfa_mode IN ('off', 'optional', 'required'));

CREATE TABLE auth.mfa_factor (
    id             uuid         NOT NULL DEFAULT auth.uuid_v7(),
    identity_id    uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    kind           varchar(10)  NOT NULL DEFAULT 'totp',
    secret_sealed  text         NOT NULL,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    confirmed_at   timestamptz  NULL,          -- NULL: enrolment started, not yet proven with a code
    last_step      bigint       NOT NULL DEFAULT 0, -- the last TOTP time step used (a code is never accepted twice)
    last_used_at   timestamptz  NULL,
    CONSTRAINT mfa_factor_pkey PRIMARY KEY (id),
    CONSTRAINT mfa_factor_kind_check CHECK (kind IN ('totp'))
);
CREATE UNIQUE INDEX mfa_factor_one ON auth.mfa_factor (identity_id, kind);

CREATE TABLE auth.recovery_code (
    identity_id    uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    code_hash      bytea        NOT NULL,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    used_at        timestamptz  NULL,
    CONSTRAINT recovery_code_pkey PRIMARY KEY (identity_id, code_hash)
);

-- The second step of a sign-in: the password (or email code) was right, the authenticator code is awaited.
CREATE TABLE auth.mfa_challenge (
    token_hash     bytea        NOT NULL,
    identity_id    uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    membership_id  uuid         NOT NULL REFERENCES auth.membership (id) ON DELETE CASCADE,
    tenant_id      uuid         NOT NULL REFERENCES auth.tenant (id),
    method         varchar(10)  NOT NULL,       -- local | otp: how the first step was done
    created_at     timestamptz  NOT NULL DEFAULT now(),
    expires_at     timestamptz  NOT NULL,
    attempts       integer      NOT NULL DEFAULT 0,
    used_at        timestamptz  NULL,
    CONSTRAINT mfa_challenge_pkey PRIMARY KEY (token_hash)
);

-- ---------------------------------------------------------------- Identity providers of a company
-- Where a company's people may also sign in: its Active Directory (Azure AD / Entra ID), Google Workspace, or any
-- OpenID Connect provider. Email domains route a sign-in to the provider; claims map to the ALIR member. The
-- connectors that sign people in through them come later (Stage 2); this is their master.
CREATE TABLE auth.identity_provider (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,
    name                    varchar(150) NOT NULL,      -- the button label
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
    -- Provider Attributes
    tenant_id               uuid         NOT NULL REFERENCES auth.tenant (id),
    kind                    varchar(20)  NOT NULL,      -- azure_ad | google | oidc
    issuer                  varchar(300) NOT NULL,
    client_id               varchar(200) NOT NULL,
    client_secret_sealed    text         NULL,
    secret_hint             varchar(4)   NULL,
    scopes                  text[]       NOT NULL DEFAULT '{openid,profile,email}',
    email_domains           text[]       NOT NULL DEFAULT '{}',
    subject_claim           varchar(60)  NOT NULL DEFAULT 'sub',
    email_claim             varchar(60)  NOT NULL DEFAULT 'email',
    name_claim              varchar(60)  NOT NULL DEFAULT 'name',
    jit_provisioning        boolean      NOT NULL DEFAULT false, -- a first sign-in makes the member
    default_role_id         uuid         NULL REFERENCES auth.role (id),
    CONSTRAINT identity_provider_pkey PRIMARY KEY (id),
    CONSTRAINT identity_provider_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT identity_provider_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT identity_provider_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT identity_provider_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT identity_provider_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    ),
    CONSTRAINT identity_provider_kind_check CHECK (kind IN ('azure_ad', 'google', 'oidc')),
    CONSTRAINT identity_provider_jit_check CHECK (NOT jit_provisioning OR default_role_id IS NOT NULL)
);
CREATE UNIQUE INDEX identity_provider_code_ci ON auth.identity_provider (tenant_id, lower(code));
CREATE INDEX idx_identity_provider_tenant ON auth.identity_provider (tenant_id) WHERE NOT is_deleted;

INSERT INTO auth.code_prefix (tenant_id, code, name, description, prefix, digits, created_by)
SELECT id, 'identity_provider', 'Penyedia Identitas', 'Kode penyedia identitas baru: IDP001, …', 'IDP', 3, '00000000-0000-7000-8000-000000000000'
FROM auth.tenant;
