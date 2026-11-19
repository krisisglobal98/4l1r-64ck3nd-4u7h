-- Self sign-up, email verification and email OTP (Stage 1C). People who are not employees (vendors, applicants of a
-- public application) sign up with their email first, verify it, complete their data in the application, and are
-- verified by the company there. A company opens sign-up in its security policy and names the role new external
-- members get. Every public answer is the same whether an email is known or not (no account probing).

ALTER TABLE auth.identity
    ADD COLUMN origin            varchar(10) NOT NULL DEFAULT 'admin', -- admin (made by an administrator) | signup
    ADD COLUMN terms_version     varchar(20) NULL,                     -- the terms accepted at sign-up
    ADD COLUMN terms_accepted_at timestamptz NULL,
    ADD CONSTRAINT identity_origin_check CHECK (origin IN ('admin', 'signup'));

-- The company's (or its application's) verification of a member: e.g. a vendor whose documents were checked.
ALTER TABLE auth.membership
    ADD COLUMN verified_at timestamptz NULL,
    ADD COLUMN verified_by uuid        NULL;

ALTER TABLE auth.security_policy
    ADD COLUMN self_signup_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN self_signup_role_id uuid    NULL REFERENCES auth.role (id),
    ADD COLUMN allow_email_otp     boolean NOT NULL DEFAULT true,
    ADD CONSTRAINT security_policy_signup_check CHECK (NOT self_signup_enabled OR self_signup_role_id IS NOT NULL);

-- Single-use mailed tokens (email verification, 24 h).
CREATE TABLE auth.email_token (
    token_hash  bytea        NOT NULL,
    identity_id uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    tenant_id   uuid         NULL REFERENCES auth.tenant (id),
    purpose     varchar(10)  NOT NULL DEFAULT 'verify',
    created_at  timestamptz  NOT NULL DEFAULT now(),
    expires_at  timestamptz  NOT NULL,
    used_at     timestamptz  NULL,
    CONSTRAINT email_token_pkey PRIMARY KEY (token_hash),
    CONSTRAINT email_token_purpose_check CHECK (purpose IN ('verify'))
);
CREATE INDEX idx_email_token_identity ON auth.email_token (identity_id);

-- One-time sign-in codes sent by email (6 digits, 10 min, 5 tries).
CREATE TABLE auth.login_otp (
    id          uuid         NOT NULL DEFAULT auth.uuid_v7(),
    identity_id uuid         NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    code_hash   bytea        NOT NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    expires_at  timestamptz  NOT NULL,
    attempts    integer      NOT NULL DEFAULT 0,
    used_at     timestamptz  NULL,
    CONSTRAINT login_otp_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_login_otp_identity ON auth.login_otp (identity_id, created_at DESC);

-- Rate limits shared by every instance of the service: one row per counted attempt, kept for a day.
CREATE TABLE auth.rate_event (
    key varchar(200) NOT NULL,
    at  timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX idx_rate_event ON auth.rate_event (key, at);
