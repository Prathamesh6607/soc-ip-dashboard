"""Gmail OAuth authentication helpers for dashboard access and sender identity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.send",
]


def _load_credentials(token_file: Path) -> Credentials | None:
    if not token_file.exists():
        return None

    try:
        creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)
    except Exception:
        token_file.unlink(missing_ok=True)
        return None

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            token_file.write_text(creds.to_json(), encoding="utf-8")
        except Exception:
            token_file.unlink(missing_ok=True)
            return None
    return creds


def get_authenticated_email(token_file: Path) -> str | None:
    """Return authenticated Gmail address from stored token, else None."""

    creds = _load_credentials(token_file)
    if not creds or not creds.valid:
        return None

    try:
        service = build("oauth2", "v2", credentials=creds)
        profile: dict[str, Any] = service.userinfo().get().execute()
        return str(profile.get("email", "")).strip() or None
    except Exception:
        return None


def authenticate_gmail(credentials_file: Path, token_file: Path) -> tuple[bool, str, str | None]:
    """Run OAuth browser flow, persist token, and return authenticated email."""

    if not credentials_file.exists():
        return (
            False,
            "Gmail credentials file not found. Add gmail_credentials.json in project and configure [gmail_api].",
            None,
        )

    try:
        flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
        try:
            creds = flow.run_local_server(port=0)
        except Exception:
            creds = flow.run_console()
        token_file.write_text(creds.to_json(), encoding="utf-8")

        service = build("oauth2", "v2", credentials=creds)
        profile: dict[str, Any] = service.userinfo().get().execute()
        email = str(profile.get("email", "")).strip() or None
        if not email:
            return False, "Authentication succeeded but could not read Gmail address.", None

        return True, f"Authenticated as {email}", email
    except Exception as exc:
        return False, f"Gmail authentication failed: {exc}", None


def clear_authentication(token_file: Path) -> None:
    """Remove stored token to force re-authentication."""

    if token_file.exists():
        token_file.unlink()
