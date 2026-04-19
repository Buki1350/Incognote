# SECURITY_REPORT.md

## 1. Architecture Overview

Incognote is split into two Rust/Axum microservices:

- **Auth Service** (`:3001`)
  - Registers users
  - Authenticates users
  - Issues JWT tokens
  - Validates tokens for other services
  - Manages user roles (`admin`, `user`)

- **Notes Service** (`:3002`)
  - Performs note CRUD and sharing
  - Enforces access control and RBAC
  - Encrypts/decrypts optional encrypted note content
  - Logs note access events

Shared data layer: PostgreSQL (`:5432`) with exactly three tables:
`users`, `notes`, `note_permissions`.

Frontend: static HTML/CSS/JS (`:8080`).

## 2. Threat Model (Basic)

### Assets

- User credentials
- Authentication tokens
- Note content
- Permission mappings

### Threat Actors

- External attacker (internet traffic)
- Authenticated malicious user (horizontal privilege escalation)
- Insider with DB read access
- Bot performing brute-force login attempts

### Main Attack Paths

- SQL injection payloads
- IDOR by changing note IDs
- JWT tampering/replay
- Stored XSS in note content
- Brute-force account attacks
- Dependency outage abuse (fail-open scenarios)

## 3. Identified Risks

- **R1: Credential compromise** via weak hashing or brute force.
- **R2: Unauthorized note access** via missing ownership/permission checks.
- **R3: Data exposure at rest** if DB is leaked and notes are plaintext.
- **R4: Token trust failure** if invalid tokens are accepted.
- **R5: XSS** if user content is rendered unsafely.
- **R6: Fail-open behavior** if auth dependency outage grants access.

## 4. Implemented Protections

- **Authentication**
  - JWT with signed HS256 tokens and expiration.
  - Auth Service validates role and identity claims.

- **Authorization and RBAC**
  - Roles: `admin` (full access), `user` (limited).
  - Notes Service checks note owner/share permission for each note operation.
  - Admin-only endpoint for role updates.

- **IDOR prevention**
  - Note queries scope by `owner_id` or explicit `note_permissions` row.
  - Unauthorized note access returns `404` to avoid identifier probing.

- **Encryption**
  - Optional AES-256-GCM for note content.
  - Encrypted payload stores nonce + ciphertext + auth tag.
  - Encryption key material comes from environment, not hardcoded.

- **Input validation and XSS reduction**
  - Username/password/note content constraints.
  - Backend sanitizes note content.
  - Frontend renders with `textContent`.

- **Brute-force protection**
  - In-memory limiter by `username + IP`.
  - 5 failures in 15 minutes triggers lockout.

- **SQL injection protection**
  - All DB operations use parameterized `sqlx` queries.

- **Logging**
  - Auth success/failure, role changes, note read/write/share/delete events.
  - Login country enrichment via external geolocation API.

## 5. Failure Scenarios

### Auth Service is down

- Notes Service token validation calls fail.
- Notes Service returns `503 Authentication service unavailable`.
- No request is allowed without explicit token validation result.

### Notes Service is down

- Auth Service remains available (login/register still works).
- Frontend displays notes-related error while auth remains functional.

### External GeoIP API is down

- Login still succeeds.
- Country logging gracefully degrades to `unknown`.

### Database unavailable

- Services return `503` for DB-dependent operations.
- No insecure fallback paths are used.

## 6. Deployment Scenario

Recommended deployment:

- Reverse proxy (TLS termination) in front of frontend + APIs.
- Compose/Kubernetes with separate services for auth, notes, DB.
- Env-managed secrets:
  - `JWT_SECRET`
  - `NOTE_ENCRYPTION_KEY`
  - `DATABASE_URL`
- Restricted network policy so DB is reachable only by backend services.
- Centralized log aggregation and alerting.

## 7. Penetration Testing Approach

### Tools

- OWASP ZAP (automated scanning)
- Burp Suite (manual auth/authorization test cases)

### Test Focus

1. Auth endpoints
- brute-force attempts
- invalid JWTs
- JWT tampering

2. Authorization
- read/update/delete notes by changing IDs
- share notes without owner/admin rights

3. Input handling
- SQLi payloads in username/note fields
- XSS payloads in note content

4. Crypto behavior
- verify encrypted notes are ciphertext in DB
- tamper ciphertext and verify decrypt failure

5. Dependency failure
- stop Auth Service and confirm Notes Service denies access

## 8. Negative Analysis (Without Protections)

- Without parameterized SQL: SQL injection can leak or modify data.
- Without IDOR checks: users can read/edit other users' notes.
- Without RBAC: non-admin users can escalate role-sensitive actions.
- Without rate limiting: brute-force success probability rises sharply.
- Without encryption option: DB compromise reveals all note contents.
- Without fail-safe auth dependency handling: auth outage could become auth bypass.
- Without sanitization/safe rendering: stored XSS compromises user sessions.
