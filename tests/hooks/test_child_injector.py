"""Tests for ChildInjector.track_and_inject() — direct injection into a root PID.

These exercise the control flow only (task scheduling, event posting); actual
Win32 injection is mocked since it's Windows-only. Real functional verification
of hook DLL injection requires a Windows box.
"""
from __future__ import annotations
import asyncio
from pathlib import Path

import pytest

import quarry.hooks.child_injector as child_injector_mod
from quarry.hooks.child_injector import ChildInjector
from quarry.models.event import EVENT_HOOK


class _FakeStore:
    def __init__(self) -> None:
        self.posted: list = []

    def post(self, event) -> None:
        self.posted.append(event)


@pytest.fixture()
def fast_settle(monkeypatch):
    """Shrink the loader-settle delay so tests don't wait 400ms each."""
    monkeypatch.setattr(child_injector_mod, "_SETTLE_DELAY", 0.01)


def _make_injector(store: _FakeStore) -> ChildInjector:
    return ChildInjector(root_pids=set(), dll_dir=Path("."), store=store)


async def test_track_and_inject_adds_to_tracked_immediately():
    store = _FakeStore()
    injector = _make_injector(store)

    injector.track_and_inject(4242)

    assert 4242 in injector._tracked


async def test_track_and_inject_runs_do_inject_after_settle_delay(fast_settle):
    store = _FakeStore()
    injector = _make_injector(store)

    injector.track_and_inject(4242)
    await asyncio.sleep(0.1)

    assert 4242 in injector._injected


async def test_track_does_not_schedule_injection(fast_settle):
    """Regression: plain track() (used by `quarry inject`) must not re-inject."""
    store = _FakeStore()
    injector = _make_injector(store)

    injector.track(4242)
    await asyncio.sleep(0.1)

    assert 4242 in injector._tracked
    assert 4242 not in injector._injected
    assert store.posted == []


async def test_windows_path_posts_auto_inject_event(monkeypatch, fast_settle):
    store = _FakeStore()
    injector = _make_injector(store)

    monkeypatch.setattr(child_injector_mod, "_WINDOWS", True)
    fake_dll = Path("quarry_hooks_x64.dll")
    monkeypatch.setattr("quarry.hooks.injector.select_dll", lambda dll_dir, pid: fake_dll)
    monkeypatch.setattr("quarry.hooks.injector.inject", lambda pid, dll: None)

    injector.track_and_inject(4242)
    await asyncio.sleep(0.1)

    assert 4242 in injector._injected
    assert len(store.posted) == 1
    event = store.posted[0]
    assert event.event_type == EVENT_HOOK
    assert event.pid == 4242
    assert event.data["hook"] == "AUTO_INJECT"


async def test_windows_path_injection_failure_posts_auto_inject_failed(monkeypatch, fast_settle):
    store = _FakeStore()
    injector = _make_injector(store)

    monkeypatch.setattr(child_injector_mod, "_WINDOWS", True)

    def _raise_select_dll(dll_dir, pid):
        raise RuntimeError("boom")

    monkeypatch.setattr("quarry.hooks.injector.select_dll", _raise_select_dll)

    injector.track_and_inject(4242)
    await asyncio.sleep(0.1)

    assert len(store.posted) == 1
    event = store.posted[0]
    assert event.event_type == EVENT_HOOK
    assert event.pid == 4242
    assert event.data["hook"] == "AUTO_INJECT_FAILED"
