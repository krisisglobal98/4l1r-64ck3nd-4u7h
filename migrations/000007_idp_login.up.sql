-- Sign-in through a company's identity provider (Stage 2): Authentication is the relying party of the company's
-- Microsoft Entra ID / Azure AD, Google Workspace or other OpenID Connect provider.
--
--   idp_login       one redirect to the provider waiting for its answer (state, nonce, PKCE verifier; 10 min, single use)
--   identity_link   + the provider it came from and when it was last used

ALTER TABLE auth.identity DROP CONSTRAINT identity_origin_check,
    ADD CONSTRAINT identity_origin_check CHECK (origin IN ('admin', 'signup', 'idp'));

ALTER TABLE auth.identity_link
    ADD COLUMN idp_id       uuid        NULL REFERENCES auth.identity_provider (id) ON DELETE SET NULL,
    ADD COLUMN last_used_at timestamptz NULL;

CREATE TABLE auth.idp_login (
    state_hash      bytea        NOT NULL,
    idp_id          uuid         NOT NULL REFERENCES auth.identity_provider (id) ON DELETE CASCADE,
    nonce           varchar(100) NOT NULL,
    code_verifier   varchar(128) NOT NULL,
    return_to       varchar(500) NULL,     -- a path of the ALIR pages (never another site)
    login_challenge varchar(100) NULL,     -- an OIDC sign-in of another application waiting for this one
    created_at      timestamptz  NOT NULL DEFAULT now(),
    expires_at      timestamptz  NOT NULL,
    used_at         timestamptz  NULL,
    CONSTRAINT idp_login_pkey PRIMARY KEY (state_hash)
);
