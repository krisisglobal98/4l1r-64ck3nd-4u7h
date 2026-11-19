DELETE FROM auth.code_prefix WHERE code = 'identity_provider';
DROP TABLE auth.identity_provider;
DROP TABLE auth.mfa_challenge;
DROP TABLE auth.recovery_code;
DROP TABLE auth.mfa_factor;
ALTER TABLE auth.security_policy DROP CONSTRAINT security_policy_mfa_check, DROP COLUMN mfa_mode;
