"""Email notification utilities for SOC approval workflow."""

from __future__ import annotations

import base64
import importlib
import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from gmail_auth import SCOPES


logger = logging.getLogger(__name__)


def parse_email_list(raw: str) -> list[str]:
    """Parse comma-separated email string into clean list."""

    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def build_approval_subject(shift: str, block_date: datetime) -> str:
    """Build subject: Cloudflare IP Blocking | shift | date."""

    normalized_shift = shift.strip().lower()
    if normalized_shift == "night":
        normalized_shift = "evening"

    return f"Cloudflare IP Blocking | {normalized_shift} | {block_date.strftime('%d %b %Y')}"


def build_approval_html(
    approver_name: str,
    shift: str,
    approved_ips: list[dict[str, str | int]],
) -> str:
    """Build HTML body with requested block instruction and approved IP table."""

    rows_html = ""
    for index, item in enumerate(approved_ips, start=1):
        rows_html += (
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{item.get('ipAddress', '')}</td>"
            f"<td>{item.get('abuseConfidenceScore', '')}</td>"
            f"<td>{item.get('country', '')}</td>"
            f"<td>{item.get('isp', '')}</td>"
            f"<td>{item.get('PATH', '')}</td>"
            f"<td>{item.get('Reason', 'Malicious Activity')}</td>"
            f"<td>{approver_name}</td>"
            f"<td>{shift}</td>"
            "</tr>"
        )

    return f"""
    <html>
      <body>
        <p>Hello Team,</p>
        <p>
          Kindly block the IPs below on Cloudflare and on the Perimeter Firewall.
        </p>

        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse;">
          <thead>
            <tr>
              <th>Sr No</th>
              <th>IP</th>
              <th>Abuse Score</th>
              <th>Country</th>
              <th>ISP</th>
              <th>Path</th>
              <th>Reason for Blocking</th>
              <th>Approved By</th>
              <th>Shift</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>

        <p>
          Remaining non-approved items are shared with Monitoring for further tracking.
        </p>
      </body>
    </html>
    """


def send_approval_email(
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    smtp_use_tls: bool,
    email_from: str,
    email_to: list[str],
    monitoring_emails: list[str],
    subject: str,
    html_body: str,
    provider: str = "auto",
    gmail_credentials_file: str | Path | None = None,
    gmail_token_file: str | Path | None = None,
    gmail_user_id: str = "me",
) -> tuple[bool, str]:
    """Send approval email via SMTP/Gmail API and return (success, message)."""

    if not email_from or not email_to:
      return False, "Email config incomplete (from/to required)."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = ", ".join(email_to)
    if monitoring_emails:
      msg["Cc"] = ", ".join(monitoring_emails)

    msg.attach(MIMEText(html_body, "html"))

    normalized_provider = (provider or "auto").strip().lower()

    if normalized_provider in {"smtp", "auto"}:
        smtp_ok, smtp_message = _send_via_smtp(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            smtp_use_tls=smtp_use_tls,
            email_from=email_from,
            email_to=email_to,
            monitoring_emails=monitoring_emails,
            message=msg,
        )
        if smtp_ok or normalized_provider == "smtp":
            return smtp_ok, smtp_message

    if normalized_provider in {"gmail_api", "auto"}:
        return _send_via_gmail_api(
            email_to=email_to,
            monitoring_emails=monitoring_emails,
            message=msg,
            credentials_file=Path(gmail_credentials_file) if gmail_credentials_file else None,
            token_file=Path(gmail_token_file) if gmail_token_file else None,
            gmail_user_id=gmail_user_id,
        )

    return False, f"Unsupported email provider: {provider}"


def _send_via_smtp(
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    smtp_use_tls: bool,
    email_from: str,
    email_to: list[str],
    monitoring_emails: list[str],
    message: MIMEMultipart,
) -> tuple[bool, str]:
    """Send email through SMTP server."""

    if not smtp_host:
        return False, "SMTP host not configured."

    all_recipients = email_to + monitoring_emails

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            if smtp_use_tls:
                server.starttls()
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
            server.sendmail(email_from, all_recipients, message.as_string())
        return True, "Approval email sent successfully."
    except Exception as exc:
        logger.exception("Failed to send approval email")
        return False, f"SMTP send failed: {exc}"


def _send_via_gmail_api(
    email_to: list[str],
    monitoring_emails: list[str],
    message: MIMEMultipart,
    credentials_file: Path | None,
    token_file: Path | None,
    gmail_user_id: str = "me",
) -> tuple[bool, str]:
    """Send email using Gmail API OAuth flow (no SMTP/app password needed)."""

    if not credentials_file or not credentials_file.exists():
        return False, "Gmail API credentials file not found. Add gmail_credentials.json and configure [gmail_api]."

    token_path = token_file or Path("gmail_token.json")

    try:
        request_module = importlib.import_module("google.auth.transport.requests")
        credentials_module = importlib.import_module("google.oauth2.credentials")
        flow_module = importlib.import_module("google_auth_oauthlib.flow")
        discovery_module = importlib.import_module("googleapiclient.discovery")

        Request = request_module.Request
        Credentials = credentials_module.Credentials
        InstalledAppFlow = flow_module.InstalledAppFlow
        build = discovery_module.build
    except Exception as exc:
        return False, f"Gmail API dependencies missing: {exc}"

    scopes = SCOPES
    creds = None

    if token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), scopes)
        except Exception:
            token_path.unlink(missing_ok=True)
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), scopes)
            creds = flow.run_local_server(port=0)
        token_path.write_text(creds.to_json(), encoding="utf-8")

    try:
        service = build("gmail", "v1", credentials=creds)
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
        service.users().messages().send(userId=gmail_user_id, body={"raw": raw_message}).execute()
        if monitoring_emails:
            return True, "Approval email sent via Gmail API (monitoring copied in CC)."
        return True, "Approval email sent via Gmail API."
    except Exception as exc:
        logger.exception("Failed to send approval email via Gmail API")
        return False, f"Gmail API send failed: {exc}"
