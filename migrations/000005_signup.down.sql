DROP TABLE auth.rate_event;
DROP TABLE auth.login_otp;
DROP TABLE auth.email_token;
ALTER TABLE auth.security_policy DROP CONSTRAINT security_policy_signup_check, DROP COLUMN allow_email_otp, DROP COLUMN self_signup_role_id, DROP COLUMN self_signup_enabled;
ALTER TABLE auth.membership DROP COLUMN verified_by, DROP COLUMN verified_at;
ALTER TABLE auth.identity DROP CONSTRAINT identity_origin_check, DROP COLUMN terms_accepted_at, DROP COLUMN terms_version, DROP COLUMN origin;
