# Pokédex Secure API

## 1. Passwords & Hashing

Passwords (submitted via `POST /signup`) are handled using **bcrypt**.

* **Parameters:** We use a cost factor of `12` and a unique random salt per user (`bcrypt.gensalt(12)`). Factor 12 is a deliberate tradeoff between brute-force resistance (offline attacks) and acceptable server latency (~300ms per authentication).
* **Timing Attack Mitigation:** During `POST /login`, to prevent revealing existing usernames through response time discrepancies, we execute a dummy bcrypt verification (`_DUMMY_BCRYPT_HASH`) whenever a username is not found in storage.
* **Errors & Logging:** Both incorrect passwords and non-existent usernames yield the exact same generic response: `{"error": "Invalid username or password"}` with HTTP `401 Unauthorized`. Passwords, hashes, and sensitive data are strictly excluded from logs and error payloads.

## 2. Access Tokens

Authentication relies on opaque, cryptographically random 256-bit bearer tokens generated via `secrets.token_hex(32)`.

* **Management:** Active tokens are stored in an in-memory dictionary mapping each token string to its authenticated username and expiration timestamp.
* **Expiration (TTL):** Tokens expire after 15 minutes (900 seconds). This short TTL significantly reduces the window of exposure should a token be leaked, without unduly disrupting the trainer's user experience. Expired tokens are purged upon verification and during subsequent token generation.
* **Verification & Identity:** On protected routes, `_authenticate_and_authorize()` inspects the `Authorization: Bearer <token>` header. The authenticated identity is strictly derived from the validated server-side token record—never trusted from user-supplied parameters or headers.

## 3. Authorization & Ownership

Core rule: users can only view and mutate **their own Pokédex documents**. This ownership check is enforced on all data endpoints: summary list (`GET /user/{user}/pokedex`) and individual entries (`GET`, `PUT`, `DELETE` on `/user/{user}/pokedex/{dex}`).

To systematically prevent IDOR (Insecure Direct Object References) and information disclosure, the request pipeline strictly follows this order:

1. **Authentication (`401`):** Verifies the Bearer token's existence, validity, and expiration.
2. **Authorization (`403`):** Ensures `authenticated_user == path_user`. If mismatched, the request is immediately aborted before inspecting files or parameters.
3. **Input Validation (`400`/`422`):** Validates `{dex}` syntax and range, enforces the 10 KB body limit, and verifies JSON schema and cross-field constraints.
4. **Resource Existence (`404`):** File existence is evaluated only after authentication, authorization, and validation succeed, ensuring attackers cannot probe for document existence across different users.

## 4. Rate Limiting

* **Login (`POST /login`):** Targeted brute-force protection tracks consecutive authentication failures per username. Reaching 5 failed attempts locks the target account for 5 minutes (returning `429 Too Many Requests`). A successful authentication resets the counter.
* **Sign-up (`POST /signup`):** An IP-based sliding-window limiter restricts registrations to 30 requests per minute. Because a `409 Conflict` response inevitably reveals whether a username is already taken, this threshold mitigates automated user enumeration and mass registration. Input validation runs prior to database lookup so malformed payloads are rejected early.

## 5. File System & Input Validation

* **Username Validation:** Constrained to `^[a-z0-9_]{3,20}$`. Special characters, path separators (`/`), dots (`.`), URL encodings (`%`), and whitespace are rejected with `422 Unprocessable Entity`.
* **Pokédex ID (`{dex}`):** Strictly validated against `^[1-9][0-9]*$` with range $[1, 1025]$. Non-numeric syntax or leading zeros return `400 Bad Request`; numbers outside the range return `422 Unprocessable Entity`.
* **JSON Schema & Cross-Field Rules (PUT):** Payload size is capped at 10 KB. Additional fields are disallowed. `types` must contain 1 or 2 valid enum values (duplicates prohibited). `attacks` must contain 1 to 20 objects with unique attack names. The internal `dex` field must match the URL path.
* **Path Traversal Prevention:** Storage paths are formed as `data/pokedex/<username>/<dex>.json`. Because `<username>` is derived solely from the authenticated session token and `<dex>` from a validated integer, file paths cannot be manipulated. Paths are further verified using `Path.resolve()` to ensure they never escape the user's directory.
* **Safe Error Handling:** Custom Flask error handlers intercept all standard HTTP errors and uncaught exceptions (including 500s), ensuring stack traces, internal paths, and implementation internals are never returned to the client.
