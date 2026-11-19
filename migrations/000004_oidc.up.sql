-- OpenID Connect provider (Stage 1B). Applications ("clients") sign their users in through Authentication with the
-- authorization code flow + PKCE (S256, required for every client); services get tokens with client_credentials.
--
--   oauth_client    a registered application. tenant_id NULL = an application of the installation (any company's
--                   members, e.g. the ALIR web itself); otherwise only that company's members sign in to it.
--   authz_request   one /oauth2/authorize call waiting for the person to sign in (the login page's "challenge")
--   auth_code       a single-use code (60 s) traded at /oauth2/token with the PKCE verifier
--   oauth_grant     what an application holds for one sign-in: rotating refresh token, scope; it ends with the
--                   sign-in session (single logout) or when revoked
-- auth.session (one sign-in of a person) also carries the SSO cookie: signed in once, other applications get a code
-- without asking again.

CREATE TABLE auth.oauth_client (
    -- Primary Key
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),

    -- Master Data
    code                    varchar(40)  NOT NULL,      -- the client_id
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
    -- Client Attributes
    tenant_id               uuid         NULL,
    module                  varchar(60)  NULL,          -- the Beranda module it is: its token carries that module's grants
    is_public               boolean      NOT NULL DEFAULT false, -- browser/mobile app: no secret (PKCE only)
    is_first_party          boolean      NOT NULL DEFAULT false, -- part of ALIR itself
    redirect_uris           text[]       NOT NULL DEFAULT '{}',
    post_logout_uris        text[]       NOT NULL DEFAULT '{}',
    scopes                  text[]       NOT NULL DEFAULT '{openid}',
    access_token_minutes    integer      NOT NULL DEFAULT 15,
    refresh_token_days      integer      NOT NULL DEFAULT 14,   -- 0: no refresh token
    secret_hash             bytea        NULL,          -- SHA-256 of a 256-bit random secret (shown once)
    secret_hint             varchar(4)   NULL,
    secret_rotated_at       timestamptz  NULL,
    service_role_id         uuid         NULL,          -- set: client_credentials allowed, with this role's grants
    last_used_at            timestamptz  NULL,

    CONSTRAINT oauth_client_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_client_code_check CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'),
    CONSTRAINT oauth_client_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT oauth_client_approval_level_check CHECK (approval_level_required IS NULL OR approval_level_required >= 1),
    CONSTRAINT oauth_client_validity_check CHECK (valid_from IS NULL OR valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT oauth_client_delete_audit_check CHECK (
        is_deleted = (deleted_at IS NOT NULL) AND (NOT is_deleted OR deleted_by IS NOT NULL)
    ),
    CONSTRAINT oauth_client_tenant_fk FOREIGN KEY (tenant_id) REFERENCES auth.tenant (id),
    CONSTRAINT oauth_client_role_fk FOREIGN KEY (service_role_id) REFERENCES auth.role (id),
    CONSTRAINT oauth_client_tokens_check CHECK (access_token_minutes BETWEEN 5 AND 120 AND refresh_token_days BETWEEN 0 AND 90),
    CONSTRAINT oauth_client_secret_check CHECK (is_public OR secret_hash IS NOT NULL),
    CONSTRAINT oauth_client_service_check CHECK (service_role_id IS NULL OR (NOT is_public AND tenant_id IS NOT NULL))
);
CREATE UNIQUE INDEX oauth_client_code_ci ON auth.oauth_client (lower(code));
CREATE INDEX idx_oauth_client_tenant ON auth.oauth_client (tenant_id) WHERE NOT is_deleted;

CREATE TABLE auth.authz_request (
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),
    challenge_hash          bytea        NOT NULL,
    client_id               uuid         NOT NULL REFERENCES auth.oauth_client (id) ON DELETE CASCADE,
    redirect_uri            text         NOT NULL,
    scope                   text[]       NOT NULL,
    state                   varchar(500) NULL,
    nonce                   varchar(500) NULL,
    code_challenge          varchar(128) NOT NULL,
    tenant_hint             varchar(40)  NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    expires_at              timestamptz  NOT NULL,
    completed_at            timestamptz  NULL,
    CONSTRAINT authz_request_pkey PRIMARY KEY (id)
);
CREATE UNIQUE INDEX authz_request_challenge ON auth.authz_request (challenge_hash);

CREATE TABLE auth.auth_code (
    code_hash               bytea        NOT NULL,
    client_id               uuid         NOT NULL REFERENCES auth.oauth_client (id) ON DELETE CASCADE,
    session_id              uuid         NOT NULL REFERENCES auth.session (id) ON DELETE CASCADE,
    identity_id             uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    membership_id           uuid         NOT NULL REFERENCES auth.membership (id) ON DELETE CASCADE,
    tenant_id               uuid         NOT NULL REFERENCES auth.tenant (id),
    redirect_uri            text         NOT NULL,
    scope                   text[]       NOT NULL,
    nonce                   varchar(500) NULL,
    code_challenge          varchar(128) NOT NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    expires_at              timestamptz  NOT NULL,
    used_at                 timestamptz  NULL,
    grant_id                uuid         NULL,          -- the grant it was traded for (a second use revokes it)
    CONSTRAINT auth_code_pkey PRIMARY KEY (code_hash)
);

CREATE TABLE auth.oauth_grant (
    id                      uuid         NOT NULL DEFAULT auth.uuid_v7(),
    client_id               uuid         NOT NULL REFERENCES auth.oauth_client (id) ON DELETE CASCADE,
    session_id              uuid         NOT NULL REFERENCES auth.session (id) ON DELETE CASCADE,
    identity_id             uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    membership_id           uuid         NOT NULL REFERENCES auth.membership (id) ON DELETE CASCADE,
    tenant_id               uuid         NOT NULL REFERENCES auth.tenant (id),
    scope                   text[]       NOT NULL,
    refresh_hash            bytea        NULL,
    previous_hash           bytea        NULL,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    last_used_at            timestamptz  NOT NULL DEFAULT now(),
    expires_at              timestamptz  NOT NULL,
    revoked_at              timestamptz  NULL,
    CONSTRAINT oauth_grant_pkey PRIMARY KEY (id)
);
CREATE UNIQUE INDEX oauth_grant_refresh ON auth.oauth_grant (refresh_hash) WHERE refresh_hash IS NOT NULL;
CREATE INDEX idx_oauth_grant_previous ON auth.oauth_grant (previous_hash) WHERE previous_hash IS NOT NULL;
CREATE INDEX idx_oauth_grant_session ON auth.oauth_grant (session_id) WHERE revoked_at IS NULL;

ALTER TABLE auth.session ADD COLUMN sso_hash bytea NULL;     -- SHA-256 of the SSO cookie of this sign-in
CREATE UNIQUE INDEX session_sso ON auth.session (sso_hash) WHERE sso_hash IS NOT NULL;
