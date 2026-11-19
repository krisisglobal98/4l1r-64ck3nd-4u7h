DROP INDEX auth.session_sso;
ALTER TABLE auth.session DROP COLUMN sso_hash;
DROP TABLE auth.oauth_grant;
DROP TABLE auth.auth_code;
DROP TABLE auth.authz_request;
DROP TABLE auth.oauth_client;
