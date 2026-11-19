DROP TABLE auth.idp_login;
ALTER TABLE auth.identity_link DROP COLUMN last_used_at, DROP COLUMN idp_id;
UPDATE auth.identity SET origin = 'admin' WHERE origin = 'idp';
ALTER TABLE auth.identity DROP CONSTRAINT identity_origin_check,
    ADD CONSTRAINT identity_origin_check CHECK (origin IN ('admin', 'signup'));
