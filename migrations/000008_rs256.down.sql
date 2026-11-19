ALTER TABLE auth.oauth_client DROP CONSTRAINT oauth_client_id_token_alg_check, DROP COLUMN id_token_alg;
DELETE FROM auth.signing_key WHERE alg = 'RS256';
ALTER TABLE auth.signing_key DROP CONSTRAINT signing_key_alg_check, DROP COLUMN alg;
