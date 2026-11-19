-- RS256 for ID tokens (OpenID Connect Core 15.1: a provider must support it; many application libraries expect it).
-- The access tokens of ALIR stay EdDSA; the JWKS publishes both keys. An application chooses its ID token algorithm.
ALTER TABLE auth.signing_key ADD COLUMN alg varchar(10) NOT NULL DEFAULT 'EdDSA',
    ADD CONSTRAINT signing_key_alg_check CHECK (alg IN ('EdDSA', 'RS256'));
ALTER TABLE auth.oauth_client ADD COLUMN id_token_alg varchar(10) NOT NULL DEFAULT 'RS256',
    ADD CONSTRAINT oauth_client_id_token_alg_check CHECK (id_token_alg IN ('RS256', 'EdDSA'));
