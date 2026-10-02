import asyncio

import pytest

from spaf.orchestration import (
    Orchestrator, ModelRouter, Budget, BudgetExceeded, ResponseCache, make_key,
)


# ── Router ────────────────────────────────────────────────────────────
def test_router_defaults_to_provider_model(monkeypatch):
    for v in ("SPAF_MODEL_PLAN", "SPAF_MODEL_ANALYZE", "SPAF_MODEL_DEFAULT"):
        monkeypatch.delenv(v, raising=False)
    r = ModelRouter()
    assert r.resolve("plan") == [None]


def test_router_env_overrides_with_fallback(monkeypatch):
    monkeypatch.setenv("SPAF_MODEL_PLAN", "big-model, mid-model")
    monkeypatch.setenv("SPAF_MODEL_DEFAULT", "fallback-model")
    r = ModelRouter()
    chain = r.resolve("plan")
    assert chain == ["big-model", "mid-model", "fallback-model", None]


# ── Budget ────────────────────────────────────────────────────────────
def test_budget_limits_calls():
    b = Budget(max_calls=2, max_chars=10_000, max_seconds=100)
    b.consume(10)
    b.consume(10)
    with pytest.raises(BudgetExceeded):
        b.consume(10)


def test_budget_limits_chars():
    b = Budget(max_calls=10, max_chars=50, max_seconds=100)
    with pytest.raises(BudgetExceeded):
        b.consume(100)


# ── Cache ─────────────────────────────────────────────────────────────
def test_cache_roundtrip(tmp_path):
    c = ResponseCache(str(tmp_path / "c.db"), enabled=True)
    k = make_key("google", "m", "sys", "prompt")
    assert c.get(k) is None
    c.set(k, "answer")
    assert c.get(k) == "answer"


def test_cache_disabled_is_noop(tmp_path):
    c = ResponseCache(str(tmp_path / "c.db"), enabled=False)
    c.set("k", "v")
    assert c.get("k") is None


# ── Orchestrator ──────────────────────────────────────────────────────
def _orch(tmp_path, complete_fn, **kw):
    cache = ResponseCache(str(tmp_path / "o.db"), enabled=kw.pop("cache", True))
    return Orchestrator(complete_fn=complete_fn, provider="test",
                        router=ModelRouter(), cache=cache)


def test_orchestrator_caches(tmp_path, monkeypatch):
    for v in ("SPAF_MODEL_PLAN", "SPAF_MODEL_DEFAULT"):
        monkeypatch.delenv(v, raising=False)
    calls = []

    async def fn(system, prompt, model):
        calls.append(model)
        return "RESULT"

    o = _orch(tmp_path, fn)
    r1 = asyncio.run(o.complete("plan", "sys", "p"))
    r2 = asyncio.run(o.complete("plan", "sys", "p"))
    assert r1 == r2 == "RESULT"
    assert len(calls) == 1  # second call served from cache


def test_orchestrator_falls_back_to_next_model(tmp_path, monkeypatch):
    monkeypatch.setenv("SPAF_MODEL_PLAN", "bad, good")
    tried = []

    async def fn(system, prompt, model):
        tried.append(model)
        return "⚠️  provider error" if model == "bad" else "OK"

    o = _orch(tmp_path, fn, cache=False)
    out = asyncio.run(o.complete("plan", "sys", "p"))
    assert out == "OK"
    assert tried[:2] == ["bad", "good"]


def test_orchestrator_budget_stops(tmp_path, monkeypatch):
    monkeypatch.setenv("SPAF_MODEL_PLAN", "a, b, c")

    async def fn(system, prompt, model):
        return "⚠️  always fails"

    o = _orch(tmp_path, fn, cache=False)
    b = Budget(max_calls=1, max_chars=10_000, max_seconds=100)
    out = asyncio.run(o.complete("plan", "sys", "p", budget=b))
    assert "budget" in out.lower() or out.startswith("⚠️")
    assert b.calls == 1  # stopped after the first consume
