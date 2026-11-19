-- Back to one company: possible only while there is one tenant (the migrated one).
DO $$ BEGIN
    IF (SELECT count(*) FROM auth.tenant) > 1 THEN
        RAISE EXCEPTION 'more than one tenant: cannot go back to single-company accounts';
    END IF;
END $$;

CREATE TABLE auth.app_user (LIKE auth.membership INCLUDING DEFAULTS);
ALTER TABLE auth.app_user DROP COLUMN tenant_id, DROP COLUMN identity_id, DROP COLUMN kind,
    ADD COLUMN password_hash text NULL, ADD COLUMN identity_issuer varchar(200) NULL, ADD COLUMN external_subject varchar(200) NULL,
    ADD COLUMN failed_logins integer NOT NULL DEFAULT 0, ADD COLUMN locked_until timestamptz NULL,
    ADD COLUMN must_change_password varchar(10) NULL, ADD COLUMN password_changed_at timestamptz NULL;
INSERT INTO auth.app_user (id, code, name, description, is_active, is_deleted, valid_from, valid_to, created_at, created_by, updated_at,
    updated_by, deleted_at, deleted_by, version, username, role_id, level_code, ownership_code, owner_code, group_code, region_code,
    wilayah_code, gmk_code, company_code, operational_unit_code, org_level1_code, org_level2_code, org_level3_code, employee_id,
    employee_code, last_login_at, password_hash, identity_issuer, external_subject, failed_logins, locked_until, must_change_password,
    password_changed_at)
SELECT m.id, m.code, m.name, m.description, m.is_active AND i.is_active, m.is_deleted, m.valid_from, m.valid_to, m.created_at, m.created_by,
    m.updated_at, m.updated_by, m.deleted_at, m.deleted_by, m.version, m.username, m.role_id, m.level_code, m.ownership_code, m.owner_code,
    m.group_code, m.region_code, m.wilayah_code, m.gmk_code, m.company_code, m.operational_unit_code, m.org_level1_code, m.org_level2_code,
    m.org_level3_code, m.employee_id, m.employee_code, m.last_login_at, i.password_hash, l.issuer, l.subject, i.failed_logins,
    i.locked_until, i.must_change_password, i.password_changed_at
FROM auth.membership m JOIN auth.identity i ON i.id = m.identity_id
LEFT JOIN LATERAL (SELECT issuer, subject FROM auth.identity_link WHERE identity_id = i.id ORDER BY created_at LIMIT 1) l ON true;
ALTER TABLE auth.app_user ADD CONSTRAINT app_user_pkey PRIMARY KEY (id),
    ADD CONSTRAINT app_user_role_fk FOREIGN KEY (role_id) REFERENCES auth.role (id),
    ADD CONSTRAINT app_user_employee_pair CHECK ((employee_id IS NULL) = (employee_code IS NULL));
CREATE UNIQUE INDEX app_user_code_ci ON auth.app_user (lower(code));
CREATE UNIQUE INDEX app_user_username_live ON auth.app_user (username) WHERE NOT is_deleted;
CREATE UNIQUE INDEX app_user_external_live ON auth.app_user (identity_issuer, external_subject) WHERE NOT is_deleted AND external_subject IS NOT NULL;
CREATE UNIQUE INDEX app_user_employee_live ON auth.app_user (employee_id) WHERE NOT is_deleted AND employee_id IS NOT NULL;

ALTER TABLE auth.mail_outbox DROP CONSTRAINT mail_outbox_identity_fk, DROP COLUMN tenant_id;
ALTER TABLE auth.mail_outbox RENAME COLUMN identity_id TO user_id;
UPDATE auth.mail_outbox SET user_id = NULL WHERE user_id NOT IN (SELECT id FROM auth.app_user);
ALTER TABLE auth.mail_outbox ADD CONSTRAINT mail_outbox_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE SET NULL;

DROP INDEX auth.idx_audit_event_at;
DROP INDEX auth.idx_audit_event_type;
ALTER TABLE auth.audit_event DROP COLUMN tenant_id;
CREATE INDEX idx_audit_event_at ON auth.audit_event (at DESC);
CREATE INDEX idx_audit_event_type ON auth.audit_event (type, at DESC);

DELETE FROM auth.session;
DROP INDEX auth.idx_session_membership_live;
ALTER TABLE auth.session DROP CONSTRAINT session_identity_fk, DROP CONSTRAINT session_membership_fk, DROP CONSTRAINT session_tenant_fk,
    DROP COLUMN identity_id, DROP COLUMN tenant_id;
ALTER TABLE auth.session RENAME COLUMN membership_id TO user_id;
ALTER TABLE auth.session ADD CONSTRAINT session_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE CASCADE;
CREATE INDEX idx_session_user_live ON auth.session (user_id) WHERE revoked_at IS NULL;

DELETE FROM auth.password_reset;
ALTER TABLE auth.password_reset DROP CONSTRAINT password_reset_identity_fk, DROP COLUMN tenant_id;
ALTER TABLE auth.password_reset RENAME COLUMN identity_id TO user_id;
ALTER TABLE auth.password_reset ADD CONSTRAINT password_reset_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE CASCADE;

DELETE FROM auth.password_history WHERE identity_id NOT IN (SELECT id FROM auth.app_user);
ALTER TABLE auth.password_history DROP CONSTRAINT password_history_identity_fk;
ALTER TABLE auth.password_history RENAME COLUMN identity_id TO user_id;
ALTER TABLE auth.password_history ADD CONSTRAINT password_history_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE CASCADE;

UPDATE auth.code_prefix SET code = 'app_user', name = 'Pengguna', description = 'Kode pengguna baru: MUS0001, …' WHERE code = 'membership';
DROP TABLE auth.membership;
DROP TABLE auth.identity_link;
DROP TABLE auth.identity;
DROP SEQUENCE auth.identity_code_seq;

ALTER TABLE auth.security_policy ADD COLUMN id smallint NOT NULL DEFAULT 1;
ALTER TABLE auth.security_policy DROP CONSTRAINT security_policy_tenant_fk, DROP CONSTRAINT security_policy_pkey, DROP COLUMN tenant_id,
    ADD CONSTRAINT security_policy_pkey PRIMARY KEY (id), ADD CONSTRAINT security_policy_one_row CHECK (id = 1);

ALTER TABLE auth.unit_access DROP CONSTRAINT unit_access_tenant_fk, DROP CONSTRAINT unit_access_pkey, DROP COLUMN tenant_id,
    ADD CONSTRAINT unit_access_pkey PRIMARY KEY (unit_code);

DROP INDEX auth.code_prefix_code_ci;
ALTER TABLE auth.code_prefix DROP CONSTRAINT code_prefix_tenant_fk, DROP COLUMN tenant_id;
CREATE UNIQUE INDEX code_prefix_code_ci ON auth.code_prefix (lower(code));

DROP INDEX auth.role_code_ci;
ALTER TABLE auth.role DROP CONSTRAINT role_tenant_fk, DROP COLUMN tenant_id;
CREATE UNIQUE INDEX role_code_ci ON auth.role (lower(code));

DROP TABLE auth.tenant;
