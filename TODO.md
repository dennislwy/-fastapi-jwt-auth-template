# TODO List
## General
- [x] add code coverage to SonarQube
- [x] add SonarQube quality gate & code coverage score badge at README.md
- [x] add pylint & pytest Github workflows

## Auth
- [ ] when login, allow "Remember me"
    - No remember me, access token expiry in `15mins`, refresh token expiry in `1 hour`
    - Remember me, access token expiry in `1 day`, refresh token expiry in `2 weeks`
- [ ] Token revocation
    - when user logged out, session will be revoked. Tokens of same session will be denied access.
    - active session info will be store in cache & database (same expiry time as the refresh token)
        - session cache
        - key: `{user_id}{session_id}`, value: `SessionInfo`
    - valid tokens (whitelist tokens) will be store in cache (same expiry as the related token)
      - active token cache
        - key: `{token_jti}`, value: `{"type": "access token", "sibling_id": "jti of sibling"}`
        - expiry same as the token
- [ ] Token reply attack prevention
    - when user refreshes tokens, old tokens (access & refresh token) will be revoked. Refresh token are for single use only
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
    - session_id
    - user_id
    - last_active
    - last_user_agent
    - last_ip_address
    - last_location
    - login_time
    - login_user_agent
    - login_ip_address
    - login_location
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
