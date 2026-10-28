"""Alert delivery: Telegram, generic webhook, email, plus a desktop hook.

Everything here is best-effort: a broken webhook or a bad SMTP password must
never break a scan, so every sender returns an error string instead of raising.
Qt-free (the desktop notification is injected by the UI as a callable).
"""

from __future__ import annotations

import json
import smtplib
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, fields
from email.message import EmailMessage
from typing import Any, Callable, Optional

from core import settings

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


@dataclass
class AlertConfig:
    desktop: bool = True
    telegram_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    email_to: str = ""

    # -- (de)serialisation --------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "AlertConfig":
        known = {f.name for f in fields(cls)}
        clean = {}
        for key, value in (data or {}).items():
            if key in known and value is not None:
                clean[key] = value
        return cls(**clean)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AlertConfig":
        return cls.from_dict(settings.section("alerts", path))

    def save(self, path: Optional[str] = None) -> None:
        settings.update_section("alerts", self.to_dict(), path)

    # -- introspection -------------------------------------------------
    @property
    def channels(self) -> list[str]:
        active = []
        if self.telegram_token and self.telegram_chat_id:
            active.append("telegram")
        if self.webhook_url:
            active.append("webhook")
        if self.smtp_host and self.email_to:
            active.append("email")
        if self.desktop:
            active.append("desktop")
        return active

    def is_configured(self) -> bool:
        return any(c in self.channels for c in ("telegram", "webhook", "email"))


def _post_json(url: str, payload: dict, timeout: int = 10,
               opener: Optional[Callable] = None) -> Optional[str]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        open_fn = opener or urllib.request.urlopen
        with open_fn(request, timeout=timeout) as response:
            response.read()
        return None
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:  # noqa: BLE001 - delivery must never raise
        return str(exc)


def send_telegram(cfg: AlertConfig, text: str, timeout: int = 10,
                  opener: Optional[Callable] = None) -> Optional[str]:
    if not (cfg.telegram_token and cfg.telegram_chat_id):
        return "not configured"
    url = TELEGRAM_API.format(token=cfg.telegram_token)
    return _post_json(
        url,
        {"chat_id": cfg.telegram_chat_id, "text": text,
         "disable_web_page_preview": True},
        timeout=timeout,
        opener=opener,
    )


def send_webhook(cfg: AlertConfig, text: str, title: str = "",
                 timeout: int = 10, opener: Optional[Callable] = None) -> Optional[str]:
    if not cfg.webhook_url:
        return "not configured"
    # "text" (Slack/n8n), "content" (Discord) and "title" in one payload so the
    # same hook works everywhere without a per-service configuration.
    payload = {"text": f"{title}\n{text}".strip(), "content": text, "title": title}
    return _post_json(cfg.webhook_url, payload, timeout=timeout, opener=opener)


def send_email(cfg: AlertConfig, subject: str, text: str,
               timeout: int = 15) -> Optional[str]:
    if not (cfg.smtp_host and cfg.email_to):
        return "not configured"
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg.smtp_user or cfg.email_to
    message["To"] = cfg.email_to
    message.set_content(text)
    try:
        with smtplib.SMTP(cfg.smtp_host, int(cfg.smtp_port), timeout=timeout) as smtp:
            if cfg.smtp_starttls:
                smtp.starttls()
            if cfg.smtp_user:
                smtp.login(cfg.smtp_user, cfg.smtp_password)
            smtp.send_message(message)
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def dispatch(
    cfg: AlertConfig,
    title: str,
    text: str,
    notifier: Optional[Callable[[str, str], None]] = None,
    opener: Optional[Callable] = None,
) -> dict[str, str]:
    """Send through every configured channel. Returns channel -> error ('' = ok)."""
    results: dict[str, str] = {}
    if cfg.desktop and notifier is not None:
        try:
            notifier(title, text)
            results["desktop"] = ""
        except Exception as exc:  # noqa: BLE001
            results["desktop"] = str(exc)
    if cfg.telegram_token and cfg.telegram_chat_id:
        results["telegram"] = send_telegram(cfg, f"{title}\n\n{text}", opener=opener) or ""
    if cfg.webhook_url:
        results["webhook"] = send_webhook(cfg, text, title=title, opener=opener) or ""
    if cfg.smtp_host and cfg.email_to:
        results["email"] = send_email(cfg, title, text) or ""
    return results


def format_scan_diff(diff: Any, subnet: str = "") -> tuple[str, str]:
    """Human summary of a ScanDiff: (title, body) in French."""
    title = f"L0p4Map — {diff.summary()}"
    if subnet:
        title += f" sur {subnet}"

    lines: list[str] = []
    if diff.new:
        lines.append("Nouveaux appareils :")
        for device in diff.new:
            lines.append(f"  + {device['mac']}  {device['ip']}  {device['name']}")
    if diff.missing:
        lines.append("Appareils absents depuis le dernier scan :")
        for device in diff.missing:
            lines.append(
                f"  - {device['mac']}  {device.get('ip') or ''}  "
                f"{device.get('hostname') or device.get('label') or ''}".rstrip()
            )
    if diff.new_ports:
        lines.append("Nouveaux ports ouverts :")
        for entry in diff.new_ports:
            lines.append(f"  * {entry['mac']}  {entry['port']}/{entry['proto']}")
    if diff.changed:
        lines.append("Changements :")
        for change in diff.changed:
            lines.append(
                f"  ~ {change['mac']}  {change['field']}: "
                f"{change['old']} -> {change['new']}"
            )
    if not lines:
        lines.append("Aucun changement détecté.")
    return title, "\n".join(lines)
