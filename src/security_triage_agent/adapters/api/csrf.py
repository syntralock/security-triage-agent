"""Stateless CSRF tokens bound to an HttpOnly development-session cookie."""

import hashlib
import hmac
import secrets


class CsrfProtector:
    cookie_name = "sta_development_session"

    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)

    def issue(self, session_id: str | None) -> tuple[str, str, bool]:
        actual_session = session_id or secrets.token_urlsafe(32)
        token = hmac.new(self._secret, actual_session.encode(), hashlib.sha256).hexdigest()
        return actual_session, token, session_id is None

    def validate(self, session_id: str | None, token: str | None) -> bool:
        if session_id is None or token is None:
            return False
        expected = hmac.new(self._secret, session_id.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, token)
