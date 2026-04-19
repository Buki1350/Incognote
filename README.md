# Incognote

Incognote is a compact security-focused shared notes application built with Rust and Axum.

## Architecture

- `auth-service` (port `3001`)
- `notes-service` (port `3002`)
- `frontend` (static UI on port `8080`)
- `postgres` (port `5432`)

### Responsibilities

- **Auth Service**
  - register/login via email
  - unique username + unique email identities
  - email verification workflow (`/verify-email`, `/resend-verification`)
  - trusted email provider allowlist (e.g. Google / Gmail)
  - JWT issuing and validation
  - role management (`admin` / `user`)
  - brute-force protection (rate limiter)
  - login geolocation logging (external API)

- **Notes Service**
  - note CRUD
  - note sharing (`read` / `write`)
  - friend invites (send/list/accept/reject) + friends list
  - direct messages limited to your friends
  - optional private-key encryption for notes and direct messages
  - RBAC + IDOR-safe access checks
  - optional AES-256-GCM note encryption
  - access auditing via logs

### Service Communication

- Notes Service validates bearer tokens by calling `POST /validate-token` on Auth Service.
- If Auth Service is unavailable, Notes Service rejects requests (`503`) by default (fail-safe).

## Database

PostgreSQL schema includes:

1. `users`
2. `notes`
3. `note_permissions`
4. `friends`
5. `direct_messages`
6. `friend_requests`

Schema file: [`database/schema.sql`](database/schema.sql)

## Security Features

- JWT authentication with expiring tokens
- email-based login and registration
- email verification before login
- trusted email-provider enforcement
- Role-based access control (`admin`, `user`)
- Parameterized SQL queries (`sqlx`) to prevent SQL injection
- IDOR prevention in note fetch/update/delete/share handlers
- friend-only direct messaging
- friend invite confirmation flow
- optional private-key encryption for notes and direct messages
- Optional AES-256-GCM encryption for note content at rest
- Input validation and backend sanitization against stored XSS
- Brute-force login protection (5 failures / 15 minutes)
- Structured audit logging of auth and note access events

## Run With Docker Compose

```bash
docker-compose up --build
```

Then open:

- Frontend: `http://localhost:8080`
- Auth health: `http://localhost:3001/health`
- Notes health: `http://localhost:3002/health`

Default bootstrap admin (from compose env):

- username: `admin`
- email: `admin@incognote.local`
- password: `Admin1234`

## Local Development

Copy `.env.example` to `.env` and adjust values for local runs.

### Auth Service

```bash
cd auth-service
set JWT_SECRET=change_this_for_local_dev_01234567890123456789
set DATABASE_URL=postgres://postgres:postgres@localhost:5432/incognote
set ADMIN_EMAIL=admin@incognote.local
set TRUSTED_EMAIL_DOMAINS=gmail.com,googlemail.com,outlook.com,hotmail.com,live.com,yahoo.com,icloud.com,proton.me,protonmail.com,incognote.local
cargo run
```

### Notes Service

```bash
cd notes-service
set NOTE_ENCRYPTION_KEY=change_this_for_local_dev_encryption_key
set AUTH_SERVICE_URL=http://localhost:3001
set DATABASE_URL=postgres://postgres:postgres@localhost:5432/incognote
cargo run
```

## Tests

Run service tests independently:

```bash
cd auth-service
cargo test

cd ../notes-service
cargo test
```

## Security Demonstration

Insecure vs fixed snippets are documented in:

- [`security_examples/insecure_examples.rs`](security_examples/insecure_examples.rs)

## Security Report

Detailed security analysis is in:

- [`SECURITY_REPORT.md`](SECURITY_REPORT.md)
