"""Notifications for "a session reached the fake shell".

Failed logins are far too frequent to notify about; a successful login to
the fake shell is the interesting, rare event. The console notifier is always
on; Telegram is enabled when ``TELEGRAM_BOT_TOKEN`` and ``TELEGRAM_CHAT_ID``
are set.

The Telegram notifier queues events and a background task sends at most one
message every ``batch_interval`` seconds, listing up to
``max_per_message`` sessions and counting the rest. A botnet that logs in a
thousand times a minute therefore still produces one message per interval.
The bot token is part of the API URL, so it is never logged.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import os
import socket
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

log = logging.getLogger(__name__)

MAX_TEXT = 4000  # Telegram's hard limit is 4096 characters


@dataclass(frozen=True)
class LoginEvent:
    session_id: str
    ts: float
    src_ip: str
    src_port: int
    username: str
    country: str | None = None
    client_version: str | None = None

    def short(self) -> str:
        where = f" ({self.country})" if self.country else ""
        return (
            f"session {self.session_id} from {self.src_ip}{where} logged in as "
            f"{self.username!r} [{self.client_version or 'unknown client'}]"
        )


class Notifier:
    name = "base"

    async def start(self) -> None:
        pass

    async def login(self, event: LoginEvent) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class ConsoleNotifier(Notifier):
    name = "console"

    async def login(self, event: LoginEvent) -> None:
        log.warning("SHELL LOGIN %s", event.short())


class NotifierHub:
    def __init__(self, notifiers: list[Notifier]) -> None:
        self.notifiers = notifiers

    async def start(self) -> None:
        for n in self.notifiers:
            await n.start()

    async def login(self, event: LoginEvent) -> None:
        for n in self.notifiers:
            try:
                await n.login(event)
            except Exception:  # a broken notifier must never break the honeypot
                log.exception("notifier %s failed", n.name)

    async def close(self) -> None:
        for n in self.notifiers:
            with contextlib.suppress(Exception):
                await n.close()


class TelegramNotifier(Notifier):
    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        batch_interval: float = 60.0,
        max_per_message: int = 10,
        max_queue: int = 500,
        api_base: str = "https://api.telegram.org",
        client: httpx.AsyncClient | None = None,
        hostname: str | None = None,
    ) -> None:
        if not token or not chat_id:
            raise ValueError("Telegram token and chat id are required")
        # httpx logs every request URL at INFO, and this URL contains the bot token.
        for name in ("httpx", "httpcore"):
            lg = logging.getLogger(name)
            lg.setLevel(max(lg.getEffectiveLevel(), logging.WARNING))
        self._url = f"{api_base}/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.batch_interval = batch_interval
        self.max_per_message = max_per_message
        self.hostname = hostname
        self._queue: deque[LoginEvent] = deque(maxlen=max_queue)
        self._dropped = 0
        self._client = client or httpx.AsyncClient(timeout=15.0)
        self._owns_client = client is None
        self._task: asyncio.Task | None = None
        self.sent_messages = 0
        self._sleep = asyncio.sleep  # replaceable in tests

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="telegram-flush")

    async def login(self, event: LoginEvent) -> None:
        if len(self._queue) == self._queue.maxlen:
            self._dropped += 1
        self._queue.append(event)

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.batch_interval)
            try:
                await self.flush()
            except Exception:  # pragma: no cover - keep the loop alive
                log.exception("telegram flush failed")

    async def flush(self) -> bool:
        """Send one message with whatever is queued. Returns True if something was sent."""
        if not self._queue:
            return False
        events = list(self._queue)
        self._queue.clear()
        dropped, self._dropped = self._dropped, 0
        return await self._post(self.format(events, dropped))

    def format(self, events: list[LoginEvent], dropped: int = 0) -> str:
        host = f" on <b>{html.escape(self.hostname)}</b>" if self.hostname else ""
        total = len(events) + dropped
        noun = "session" if total == 1 else "sessions"
        lines = [f"\U0001f36f <b>ssh-honeypot</b>{host}: {total} {noun} reached the fake shell"]
        for e in events[: self.max_per_message]:
            when = datetime.fromtimestamp(e.ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
            where = f" {html.escape(e.country)}" if e.country else ""
            lines.append(
                f"\n<code>{html.escape(e.src_ip)}</code>{where} as "
                f"<code>{html.escape(e.username[:64])}</code>\n"
                f"{html.escape((e.client_version or 'unknown client')[:80])} · {when}\n"
                f"session <code>{html.escape(e.session_id)}</code>"
            )
        extra = len(events) - self.max_per_message + dropped
        if extra > 0:
            lines.append(f"\n… and {extra} more")
        text = "\n".join(lines)
        if len(text) > MAX_TEXT:
            text = text[: MAX_TEXT - 20] + "\n…(truncated)"
        return text

    async def _post(self, text: str, attempts: int = 3) -> bool:
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        for attempt in range(1, attempts + 1):
            try:
                resp = await self._client.post(self._url, json=payload)
            except httpx.HTTPError as exc:
                log.warning("telegram request failed (%s), attempt %d", type(exc).__name__, attempt)
                await self._sleep(min(2**attempt, 30))
                continue
            if resp.status_code == 200:
                self.sent_messages += 1
                return True
            if resp.status_code == 429:
                retry_after = 5
                with contextlib.suppress(ValueError, KeyError, TypeError):
                    retry_after = int(resp.json()["parameters"]["retry_after"])
                log.warning("telegram rate limited, retrying in %ss", retry_after)
                await self._sleep(min(retry_after, 60))
                continue
            log.warning("telegram API returned HTTP %s", resp.status_code)
            return False  # other 4xx: bad token/chat id, retrying will not help
        return False

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        with contextlib.suppress(Exception):
            await self.flush()
        if self._owns_client:
            await self._client.aclose()


def build_notifiers(batch_interval: float = 60.0, max_per_message: int = 10) -> NotifierHub:
    notifiers: list[Notifier] = [ConsoleNotifier()]
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if token and chat:
        notifiers.append(
            TelegramNotifier(
                token,
                chat,
                batch_interval=batch_interval,
                max_per_message=max_per_message,
                hostname=os.environ.get("HONEYPOT_NAME") or socket.gethostname(),
            )
        )
        log.info("Telegram notifications enabled")
    elif token or chat:
        log.warning("only one of TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID is set; Telegram disabled")
    return NotifierHub(notifiers)
