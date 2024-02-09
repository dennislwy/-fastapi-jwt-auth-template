class AuthException(Exception):
    pass


class InvalidToken(AuthException):
    pass


class TokenExpired(AuthException):
    pass


class TokenRevoked(AuthException):
    pass


class InvalidSession(AuthException):
    pass


class SessionExpired(AuthException):
    pass


class SessionRevoked(AuthException):
    pass
