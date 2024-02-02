# TODO List
## General

## Auth
- [ ] when login, allow "Remember me" (refresh token 30 days)
- [ ] Token revocation
    - when user logged out, session will be revoked. Tokens of same session will be denied access.
- [ ] Token reply attack prevention
    - when user refreshes tokens, old tokens will be revoked. Refresh token are for single use only
- [ ] Token reuse attack prevention
    - As security measures, session will be revoke if revoked token was reused

## Login
- [ ] `/login`, get JWT tokens
- [ ] `/logout`, revoke session
- [ ] `/refresh`, refresh JWT tokens
- [ ] Password management
    - [ ] `/change-password`
    - [ ] `/forgot-password`, send password reset magic link to user email
    - [ ] `/reset-password`, reset password

## User
- [ ] register new user
- [ ] invite new user (by sending invitation email with link, link will expire in 7 days)
- [ ] verify new user (by sending email to click a magic link or enter OTP, will expire in X hours)

## Session Tracking
- [ ] user able to view all active session (like GitHub)
    - last active time
    - browser info (e.g: Google Chrome (Windows))
    - sign in
        - time
        - IP address
        - location info
        - geo location (e.g: Puchong, Selangor, Malaysia)
        - coordinate
- [ ] user can revoke selective session(s) or all sessions

## Two-factor Authentication
- [ ] Enroll 2FA via OTP app
- [ ] Enroll 2FA & send OTP via email
- [ ] Enroll 2FA & send OTP via SMS

## Caching
- [ ] In-memory
- [ ] Redis
- [ ] Memcached

## API Protection
- [ ] Rate limiting
- [ ] CORS
- [ ] XSS attacks
- [ ] CSRF attacks

## Docker

## Tests
- [ ] Unit Tests
