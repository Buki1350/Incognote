//! Security demonstration snippets for instructor review.
//! These examples are not executed; they show insecure vs secure patterns.

/// ---------------------------------------------------------------------------
/// 1) IDOR (Insecure Direct Object Reference)
/// ---------------------------------------------------------------------------
/// INSECURE:
/// - Fetching by note id only lets any authenticated user read any note.
///
/// ```rust
/// // Vulnerable: no owner/shared check
/// let note = sqlx::query_as::<_, Note>("SELECT * FROM notes WHERE id = $1")
///     .bind(note_id)
///     .fetch_one(&pool)
///     .await?;
/// ```
///
/// FIXED (used in notes service):
/// - Query includes `(owner_id = user OR permission row exists)`.
/// - Returns 404 when user has no access, preventing ID probing.
///
/// ```rust
/// SELECT n.*
/// FROM notes n
/// LEFT JOIN note_permissions np ON np.note_id = n.id AND np.user_id = $2
/// WHERE n.id = $1 AND (n.owner_id = $2 OR np.user_id = $2)
/// ```

/// ---------------------------------------------------------------------------
/// 2) Hardcoded cryptographic key
/// ---------------------------------------------------------------------------
/// INSECURE:
///
/// ```rust
/// static ENCRYPTION_KEY: &[u8; 32] = b"hardcoded-demo-key............";
/// ```
///
/// Why vulnerable:
/// - Key leaks through source code / logs / backups.
/// - Rotation is impossible without redeploying code.
///
/// FIXED (used in notes service):
/// - Read `NOTE_ENCRYPTION_KEY` from environment.
/// - Derive AES key via SHA-256 from provided secret material.

/// ---------------------------------------------------------------------------
/// 3) Fail-open auth dependency
/// ---------------------------------------------------------------------------
/// INSECURE:
///
/// ```rust
/// // Vulnerable: allows request when auth service fails
/// match auth_client.validate_token(token).await {
///     Ok(user) => user,
///     Err(_) => allow_anyway_user(),
/// }
/// ```
///
/// FIXED (used in notes service):
/// - On auth-service network failure => HTTP 503 and deny request.
/// - Only explicit `valid: true` from auth service allows access.

/// ---------------------------------------------------------------------------
/// 4) Unsanitized note rendering (stored XSS)
/// ---------------------------------------------------------------------------
/// INSECURE:
///
/// ```rust
/// let stored = payload.content; // raw HTML/JS retained
/// ```
///
/// FIXED:
/// - Backend escapes HTML special chars before storage.
/// - Frontend renders text using `textContent`, not `innerHTML`.

/// ---------------------------------------------------------------------------
/// 5) No brute-force protection on login
/// ---------------------------------------------------------------------------
/// INSECURE:
/// - Repeated password attempts with no lockout.
///
/// FIXED (used in auth service):
/// - In-memory limiter tracks `username + ip`.
/// - Blocks after 5 failures in 15 minutes.
