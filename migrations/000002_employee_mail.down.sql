DROP TABLE auth.mail_outbox;
DROP INDEX auth.app_user_employee_live;
ALTER TABLE auth.app_user DROP CONSTRAINT app_user_employee_pair, DROP COLUMN employee_code, DROP COLUMN employee_id;
