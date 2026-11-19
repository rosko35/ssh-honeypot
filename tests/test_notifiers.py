"""Notifier tests. The Telegram API is mocked: no message ever leaves the machine."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from sshhoneypot.notifiers import (
    ConsoleNotifier,
    LoginEvent,
    NotifierHub,
    TelegramNotifier,
    build_notifiers,
)

TOKEN = "123456:TEST-TOKEN-never-real"


def event(i: int = 1, user: str = "root") -> LoginEvent:
    return LoginEvent(
        session_id=f"{i:012x}",
        ts=1_795_000_000.0 + i,
        src_ip=f"198.51.100.{i}",
        src_port=40000 + i,
        username=user,
        country="NL",
        client_version="SSH-2.0-libssh_0.9.6",
    )


def mock_client(responses: list[httpx.Response], seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responses.pop(0) if responses else httpx.Response(200, json={"ok": True})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_batches_events_into_one_message():
    seen: list[httpx.Request] = []
    tg = TelegramNotifier(TOKEN, "42", client=mock_client([], seen), max_per_message=2,
                          api_base="https://telegram.invalid")  # fmt: skip
    for i in range(1, 6):
        await tg.login(event(i))
    assert await tg.flush() is True
    assert await tg.flush() is False  # queue is empty now
    assert len(seen) == 1
    body = json.loads(seen[0].content)
    assert body["chat_id"] == "42" and body["parse_mode"] == "HTML"
    assert "5 sessions reached the fake shell" in body["text"]
    assert body["text"].count("<code>198.51.100.") == 2
    assert "… and 3 more" in body["text"]
    assert seen[0].url.host == "telegram.invalid"
    await tg.close()


async def test_hostile_username_is_escaped():
    tg = TelegramNotifier(TOKEN, "42", client=mock_client([], []))
    text = tg.format([event(1, user="<b>x</b>&<a href='y'>")])
    assert "<b>x</b>" not in text.split("\n", 1)[1]
    assert "&lt;b&gt;x&lt;/b&gt;&amp;&lt;a href=&#x27;y&#x27;&gt;" in text
    await tg.close()


async def test_retries_after_429_and_never_logs_the_token(caplog):
    seen: list[httpx.Request] = []
    responses = [httpx.Response(429, json={"parameters": {"retry_after": 3}}), httpx.Response(200)]
    tg = TelegramNotifier(TOKEN, "42", client=mock_client(responses, seen))
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    tg._sleep = fake_sleep
    await tg.login(event())
    with caplog.at_level(logging.DEBUG):
        assert await tg.flush()
    assert len(seen) == 2 and sleeps == [3]
    assert TOKEN not in caplog.text
    await tg.close()


async def test_bad_token_does_not_retry():
    seen: list[httpx.Request] = []
    tg = TelegramNotifier(TOKEN, "42", client=mock_client([httpx.Response(401)], seen))
    await tg.login(event())
    assert await tg.flush() is False
    assert len(seen) == 1
    await tg.close()


async def test_queue_is_bounded():
    tg = TelegramNotifier(TOKEN, "42", client=mock_client([], []), max_queue=3)
    for i in range(10):
        await tg.login(event(i))
    assert len(tg._queue) == 3 and tg._dropped == 7
    assert "10 sessions" in tg.format(list(tg._queue), tg._dropped)
    await tg.close()


async def test_hub_isolates_failures(caplog):
    class Broken(ConsoleNotifier):
        name = "broken"

        async def login(self, event):
            raise RuntimeError("boom")

    got: list[LoginEvent] = []

    class Collect(ConsoleNotifier):
        async def login(self, event):
            got.append(event)

    hub = NotifierHub([Broken(), Collect()])
    await hub.login(event())
    assert len(got) == 1
    assert "notifier broken failed" in caplog.text


async def test_console_notifier_logs(caplog):
    with caplog.at_level(logging.WARNING):
        await ConsoleNotifier().login(event())
    assert "SHELL LOGIN session 000000000001 from 198.51.100.1 (NL)" in caplog.text


async def test_build_notifiers_from_env(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert [n.name for n in build_notifiers().notifiers] == ["console"]
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", TOKEN)
    assert [n.name for n in build_notifiers().notifiers] == ["console"]  # chat id missing
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
    hub = build_notifiers(batch_interval=120)
    assert [n.name for n in hub.notifiers] == ["console", "telegram"]
    assert hub.notifiers[1].batch_interval == 120
    await hub.close()  # never started, nothing queued: no request is made


def test_requires_token_and_chat():
    with pytest.raises(ValueError):
        TelegramNotifier("", "42")
