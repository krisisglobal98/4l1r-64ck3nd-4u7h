# ALIR Authentication service

Sign-in, accounts (Pengguna), roles and grants (Peran & Hak Akses), unit module access (Akses Modul Unit), the
security policy, sessions and the audit log of ALIR. Go 1.25, PostgreSQL (schema `auth`), standard library HTTP.
It answers the contract the ALIR frontend reads (`../ALIR/docs/auth-api.md`; `src/services/api/demoApi.ts` behaves
the same way).

```bash
cp .env.example .env        # DATABASE_URL, AUTH_ADMIN_PASSWORD (the first administrator), PM_SERVICE_URL
make migrate-up
make run                    # http://localhost:8083
```
On the first start with no account, `admin` is made with `AUTH_ADMIN_PASSWORD` and must change it at the first
sign-in; the built-in roles get their default grants. In ALIR: `VITE_AUTH_API_URL=/auth-api` (the Vite dev server
proxies it here).

Tests: `make test` (unit), `make test-e2e` (over HTTP: real handlers and `TEST_DATABASE_URL`, a fake Portal Master,
a clock the tests move).

## Companies, people and memberships (multi-tenant)
One installation serves many companies (tenants); Authentication is their identity provider.

| Table | What it is |
|---|---|
| `auth.tenant` | a company; its `code` is its address (`gan` → gan.alir.example) |
| `auth.identity` | the **person**, global: one password, one lockout, optional sign-in email (unique), `is_platform_admin` |
| `auth.identity_link` | a federated identity of the person (issuer + subject: AD, Google, … — connectors come later) |
| `auth.membership` | the person **in one company**: username there, role, organisation scope, employee, kind (`workforce` / `external`) |

Roles and grants, unit module access, the security policy, generated codes, sessions, the audit log and mail belong
to a company. Isolation here is in every query (Authentication is the one service that crosses companies: sign-in by
email looks at all of them), proven by the e2e tenant suite; Portal Master uses Row-Level Security.

| Situation | Behaviour |
|---|---|
| Sign-in | `POST /auth/login {username, password, tenant?}`; `username` may be an email. `tenant` = company code, or the `X-Tenant` header of its address |
| Member of several companies | after a correct password: 409 `TENANT_CHOICE` with `details.tenants`; sign in again with the chosen `tenant` |
| One username in several companies | 409 `TENANT_REQUIRED` (sign in with email, or name the company) |
| Switch company | `POST /auth/switch-tenant {tenant}`: the session moves, new token, refresh cookie rotates; tokens of the company left stop |
| Token | `sub` = the person (identity), `mid` = the membership, `tid` = the company; Portal Master scopes every row by `tid` |
| Password and lockout | one per person: the rules are the **strictest** of their companies; session hours, idle and concurrency follow the company signed in to |
| Adding a member whose email already has an identity | the same person joins (keeps their password); an administrator cannot set the password of a person who is a member of another company too (reset link by mail instead) |
| Failed sign-ins | recorded in every company the person is a member of |
| Platform administrator | `GET/POST /platform/tenants`, `PUT /platform/tenants/{id}`: a new company is provisioned (built-in roles + default grants, policy, code prefixes) with its first Admin; a deactivated company signs no one in and its sessions end |

Migration 000003 moved every account into the first company "Grup Agro Nusantara" (`00000000-0000-7000-8000-0000000000a1`,
code `gan`); identity id = membership id = the old account id, so audit and `created_by` references stay valid. The
first administrator (`MUS0000`) is the platform administrator.

## How a session works
| Step | What happens |
|---|---|
| `POST /auth/login` | argon2id check; 5 failures (policy) lock the person; answer `{token, expiresAt, user, access, mustChangePassword, tenant, tenants, platformAdmin}` and an httpOnly `SameSite=Strict` refresh cookie (path `AUTH_COOKIE_PATH`) |
| access token | JWS EdDSA (Ed25519), 15 min, `iss`/`aud: alir`/`sub`/`mid`/`tid`/`sid`/`jti`, the member's grants (Admin: `full`). Public key at `/.well-known/jwks.json` |
| expired token | any service answers 401 `TOKEN_EXPIRED`; ALIR calls `POST /auth/refresh` once and repeats the call |
| `POST /auth/refresh` | rotates the refresh token; an old one shown again ends the session (stolen), except a second tab within 20 s (409 `REFRESH_RACE`, retried) |
| every request here | the session and the account are read again: a revoked session, an inactive account or a changed role apply at once |
| must change password | nothing else is allowed, and the token grants nothing (Portal Master refuses it) until the password is changed |
| logout, reset, admin revoke, deactivation | the sessions end (`revoked_at`) |

Every time check stored in the database (lock, session expiry, idle, refresh grace, password expiry, reset links)
uses the database's `now()`: one clock for every instance. Only the token's `exp` is checked on the server clock.

## Accounts and employees
A membership may belong to one employee of that company's Portal Master (Karyawan): `employee_id` + `employee_code`
on `auth.membership`, no foreign key across services; one employee has at most one live membership per company.

| Rule | Behaviour |
|---|---|
| One employee, at most one live account | a second account for the same employee is refused (422 `employeeCode`); a deleted account frees it |
| An account without an employee | allowed: the first administrator, system or integration accounts, vendors (they need a name) |
| Name and email | the name of a linked account is the employee's (also after a rename in Portal Master); the email is the employee's email in Master Karyawan |
| Employee inactive or deleted | the account cannot sign in (403 `EMPLOYEE_INACTIVE`), its sessions and refreshes stop (401); it signs in again when the employee is active |
| The form | `GET /users/employee-options`: the employees with the account each already has |

## Mail
Written to `auth.mail_outbox` in the transaction that causes it and sent by a background worker over SMTP (retries
after 1 min, 5 min, 15 min, 1 h, 3 h; then `failed`). Never a password in a mail.

| Mail | When | To |
|---|---|---|
| `account_created` | an account linked to an employee is made (username and where to sign in) | the employee's email |
| `password_forgot` | `POST /auth/password/forgot` (link valid 1 h) | the employee's email; none without one (same answer either way) |
| `password_reset_link` | `POST /users/:id/reset-link` (24 h): answers `{link: null, sentTo: "b***@…"}` | the employee's email; without one the link is answered to the administrator |
| `password_changed` | a password is changed or reset | the employee's email |

**Where to set it up:** the person's address is the **Email** field of **Master Karyawan** (Portal Master); the server
that sends is the `SMTP_*` settings of this service's `.env`:
```
SMTP_HOST=smtp.office365.com      # empty: mail waits in auth.mail_outbox
SMTP_PORT=587
SMTP_USERNAME=no-reply@perusahaan.co.id
SMTP_PASSWORD=...
SMTP_FROM="ALIR <no-reply@perusahaan.co.id>"
SMTP_TLS=starttls                 # starttls (587) | tls (465) | none (local catcher only)
APP_BASE_URL=https://alir.perusahaan.co.id   # links in mail
```
**Never mail strangers from a test installation:** set `SMTP_ALLOW_ONLY` (comma-separated addresses `a@b.co` or
domains `@b.co`); mail to any other address is held (`failed`, "Ditahan: …") and never handed to the server. Leave it
empty in production only.

For development, a local catcher: `docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit`, then `SMTP_HOST=localhost`,
`SMTP_PORT=1025`, `SMTP_TLS=none`, and read the mail at http://localhost:8025. Mail queued before SMTP was set is
sent once the service restarts with it.

## Accounts and scope
The organisation scope of an account is Portal Master unit codes (group → region → wilayah → company → operational
unit → organisation levels 1–3), checked against a copy of the Portal Master tree (read with a service token, at most
1 min old; `POST /org/sync` reads it again): required at the account's level, optional above, cleared below, each
code under the one chosen above it, active units only. Owner and GMK are retired and cleared.

## Layout
```
cmd/auth-service/     wiring and server
internal/auth/        the service: session.go (sign-in, refresh, passwords), users.go, roles.go, admin.go
                      (policy, unit access, sessions, audit, organisation), scope.go, org.go (Portal Master copy),
                      service.go (effective access, audit, Authenticate), http.go (routes, cookie)
internal/mail/        SMTP sender, the outbox worker
internal/token/       Ed25519 signing keys (auth.signing_key), JWS, JWKS
internal/password/    argon2id and the policy's password rules
internal/catalog/     modules → menus → actions and the built-in roles' grants (catalog.json, from the frontend)
internal/platform/    shared with ALIR_PM_SERVICE: apperr, database, httpx, record, codeprefix
migrations/           golang-migrate (schema auth)
```
`catalog.json` is exported from ALIR (`PERMISSION_CATALOG` and the built-in roles); export it again when the frontend
catalog changes.

## OpenID Connect provider (single sign-on for other applications)
Discovery: `{AUTH_PUBLIC_URL}/.well-known/openid-configuration`. In production `AUTH_ISSUER` = `AUTH_PUBLIC_URL`
(the public URL of this service), and Portal Master's `PM_AUTH_ISSUER` is the same value.

| Endpoint | What it does |
|---|---|
| `GET /oauth2/authorize` | authorization code flow. **PKCE S256 is required for every client**; `redirect_uri` must match a registered one exactly (never redirected otherwise); `prompt=login|none`; `tenant=` picks the company. Already signed in (SSO cookie `alir_sso`) → a code at once; otherwise → the ALIR login page with `?login_challenge=` |
| `GET /oauth2/authorize/request` | what the login page shows for a challenge (the application's name, the company) |
| `POST /oauth2/authorize/complete` | the login page, after the password (and a required password change), finishes the challenge → `{redirect}` back to the application |
| `POST /oauth2/token` | `authorization_code` (code single-use, 60 s; a replayed code ends what it bought), `refresh_token` (rotates; an old one reused after 20 s ends the grant), `client_credentials` (a company's confidential application with a **service role**: the token carries that role's grants). Client auth: Basic, form, or none for a public application |
| `GET /oauth2/userinfo` | the person's claims by scope |
| `POST /oauth2/revoke` | ends a refresh token (RFC 7009) |
| `GET /oauth2/logout` | ends the sign-in session: every application's refresh stops, the SSO cookie goes; then a registered `post_logout_redirect_uri` (with `state`) or the login page |

Tokens: the access token is the same JWS as the ALIR web's (`aud: alir`, `sub`/`mid`/`tid`) plus `client_id` and
`scope`; with `dod.access` it carries the person's grants, limited to the application's **module** menus. The ID token
(`aud` = client_id) has `nonce`, `auth_time`, `sid`, `tid`, `tenant`, and `name`/`preferred_username` (profile),
`email` (email). ID tokens are signed **RS256** by default (OIDC Core requires a provider to offer it; nearly every library expects
it) or EdDSA when the application asks (`idTokenAlg`). Access tokens stay EdDSA (Portal Master verifies only those;
it ignores the RSA key). The JWKS publishes both public keys.

Applications (`/auth/clients`, page Aplikasi Terhubung): a company's administrator registers the company's
applications (only that company's members sign in to them); the platform administrator also registers applications
of the installation (`platform: true`, every company). Confidential (server, secret shown once, `POST
/auth/clients/{id}/secret` rotates it) or public (browser/mobile, PKCE only). The ALIR web itself is the platform
application `alir-web` (made at start); it keeps its own httpOnly-cookie session and its login page is the hosted
login of the provider. Consent screens are not asked: an application is trusted by its registration.

## Self sign-up, email verification, email codes (vendors, applicants)
A company opens sign-up in its security policy (`selfSignupEnabled` + `selfSignupRole`, never Admin). People who are
not employees sign up at `/signup?tenant=<code>`; they verify their email, sign in, complete their data in the
application, and the company (or its application) verifies them.

| Endpoint | Behaviour |
|---|---|
| `POST /auth/signup {tenant, email, name, password, acceptTerms, captcha?}` | 202 `check_email` **always**: a new email gets a verification link (24 h); one waiting gets it again (the new password is ignored); one that has an account gets a notice to sign in. An external member signs in only after verifying (403 `EMAIL_UNVERIFIED`) |
| `POST /auth/email/verify {token}` / `POST /auth/email/resend {email}` | single-use link; resend answers the same for every email |
| `POST /auth/otp/request {email}` / `POST /auth/otp/verify {email, code, tenant?}` | 6-digit code, 10 min, 5 tries, one at a time; a correct code also confirms the email. Per company: `allowEmailOtp` |
| `POST /auth/join {tenant}` | a signed-in person joins another company that accepts sign-ups (external member) |
| `POST /users/{id}/access {role?, active?, verified?}` | administrators, or an application with a `client_credentials` token whose service role may update users (e.g. a tender application after checking a vendor's documents); only an Admin makes another Admin. `verifiedAt` is in the member and the ID token (`member_verified`) |

Abuse protection: rate limits in `auth.rate_event` (every instance shares them; per email and per address: sign-up,
resend, codes, code tries, password sign-in per address) answer 429 `RATE_LIMITED` with `retryAfterSeconds`; behind a
proxy set `AUTH_TRUST_PROXY=true` so the address is the client's. Captcha (off by default):
`AUTH_CAPTCHA_PROVIDER=turnstile|hcaptcha`, `AUTH_CAPTCHA_SECRET`, `AUTH_CAPTCHA_SITE_KEY` (the login options give
the site key to the pages). Terms: `AUTH_TERMS_VERSION`, `AUTH_TERMS_URL` (recorded on the identity at sign-up). An
hourly job removes sign-ups not verified within 7 days and old counters, codes and tokens.

## Multi-factor authentication (authenticator app)
MFA belongs to the person (one authenticator for every company). Company policy `mfaMode`: `off` (not offered) |
`optional` | `required` (an administrator can require it only after enrolling themselves).

| Step | Behaviour |
|---|---|
| Sign-in of a person with an authenticator | after the password (or email code): 401 `MFA_REQUIRED` with `details.mfaToken` (5 min, 5 tries); `POST /auth/mfa/verify {mfaToken, code \| recoveryCode}` opens the session. Wrong codes count toward the person's lockout; the failure count is cleared only when the whole sign-in succeeds |
| Required and not enrolled | the session opens with `mustEnrollMfa: true`; its token grants nothing (403 `MFA_ENROLL_REQUIRED`), no OIDC code, until enrolled |
| Enrol | `POST /auth/mfa/totp/start` (secret + `otpauth://` URL), `POST /auth/mfa/totp/confirm {code}` → 10 recovery codes shown once; `GET /auth/mfa`; `POST /auth/mfa/recovery-codes {code}`; `POST /auth/mfa/disable {code \| recoveryCode}` (refused while a company of the person requires MFA) |
| Lost phone | `POST /users/{id}/mfa/reset` (administrator; refused for a person who is a member of another company too) |

TOTP: RFC 6238 (SHA-1, 30 s, 6 digits, ±1 step), a used step is never accepted again. Secrets are sealed with
AES-256-GCM under `AUTH_SECRET_KEY` (32 bytes base64, the same on every instance; keep it safe).

## Identity providers
`/auth/identity-providers` (menu Penyedia Identitas, grant `auth.security`): a company's Microsoft Entra ID / Azure AD,
Google Workspace or other OIDC provider: issuer (https), client id, client secret (sealed, write-only: answered as
`secretSet` + `secretHint`), scopes (openid required), **email domains** (one active provider per domain in the
installation), claim mapping (Entra ID subject defaults to `oid`), just-in-time membership with an initial role (never
Admin). Codes IDP001, … per company.

## Sign-in through a company's identity provider (Entra ID / Azure AD, Google, OIDC)
Authentication is the relying party. Register the **Redirect URI** shown on the Penyedia Identitas page
(`{AUTH_PUBLIC_URL}/auth/idp/callback`) at the provider, then add the provider (issuer, client id, client secret,
email domains).

| Step | Behaviour |
|---|---|
| Buttons | `GET /auth/login-options?tenant=` lists the company's active providers; `POST /auth/idp/discover {email}` finds the provider of an email's domain ("Lanjut dengan …") |
| `GET /auth/idp/start?tenant=&idp=&login_challenge=&return=` | redirect to the provider: code flow + PKCE S256, state (10 min, single use) and nonce; Google gets `hd` for one Workspace domain |
| `GET /auth/idp/callback` | code exchanged (client_secret_post), ID token checked: RS256/ES256 with the provider's JWKS (re-read on an unknown key), `iss`, `aud`/`azp`, `exp`, `nonce` |
| The person | 1) the account linked before (issuer + subject; Entra ID subject = `oid`); 2) the email, only of a domain registered on the provider and not `email_verified: false` (Entra ID: `email`, then `preferred_username`/`upn`), then linked; 3) just-in-time: a new workforce member with the initial role (identity without a password). Otherwise `NOT_REGISTERED` |
| Then | the rules of every sign-in (inactive, employee, required MFA enrolment, the person's authenticator) |
| Back to ALIR | signed in: cookies + `/auth/sso-done?login_challenge=|return=` (a path of ALIR only); authenticator awaited: `/login?mfa=`; refused: `/login?sso_error=CODE` |

Errors: `IDP_UNAVAILABLE`, `IDP_UNREACHABLE`, `IDP_STATE`, `IDP_REFUSED`, `IDP_TOKEN`, `NOT_REGISTERED`, `NOT_MEMBER`,
`INACTIVE`, `EMPLOYEE_INACTIVE`. Setup per provider: Entra ID issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`
(single tenant; scopes openid profile email); Google issuer `https://accounts.google.com`.
