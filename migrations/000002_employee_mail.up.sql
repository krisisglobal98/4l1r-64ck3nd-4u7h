-- 1. An account may belong to one employee (Portal Master → Karyawan): one employee has at most one live account;
--    an account without an employee is allowed (the first administrator, system or integration accounts, vendors).
--    The employee's name and email come from Portal Master; while the employee is inactive the account cannot sign
--    in. Ids across services: no foreign key; the code is kept too (the business key Portal Master answers by).
ALTER TABLE auth.app_user
    ADD COLUMN employee_id   uuid        NULL,
    ADD COLUMN employee_code varchar(40) NULL,
    ADD CONSTRAINT app_user_employee_pair CHECK ((employee_id IS NULL) = (employee_code IS NULL));
CREATE UNIQUE INDEX app_user_employee_live ON auth.app_user (employee_id) WHERE NOT is_deleted AND employee_id IS NOT NULL;

-- 2. Mail to send (forgot password, reset links, account notices), written in the transaction of what causes it and
--    sent by a background worker over SMTP with retries. Never a password in a mail.
CREATE TABLE auth.mail_outbox (
    id              uuid         NOT NULL DEFAULT auth.uuid_v7(),
    kind            varchar(30)  NOT NULL, -- password_forgot | password_reset_link | account_created | password_changed
    user_id         uuid         NULL,
    to_address      varchar(254) NOT NULL,
    subject         varchar(200) NOT NULL,
    body_text       text         NOT NULL,
    status          varchar(10)  NOT NULL DEFAULT 'pending', -- pending | sent | failed
    attempts        integer      NOT NULL DEFAULT 0,
    last_error      varchar(500) NULL,
    next_attempt_at timestamptz  NOT NULL DEFAULT now(),
    created_at      timestamptz  NOT NULL DEFAULT now(),
    sent_at         timestamptz  NULL,
    CONSTRAINT mail_outbox_pkey PRIMARY KEY (id),
    CONSTRAINT mail_outbox_user_fk FOREIGN KEY (user_id) REFERENCES auth.app_user (id) ON DELETE SET NULL,
    CONSTRAINT mail_outbox_status_check CHECK (status IN ('pending', 'sent', 'failed'))
);
CREATE INDEX mail_outbox_due ON auth.mail_outbox (next_attempt_at) WHERE status = 'pending';
