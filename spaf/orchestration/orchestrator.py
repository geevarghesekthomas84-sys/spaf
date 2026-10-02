"""
Orchestrator — ties the router, cache, budget, and fallback chain around the
provider layer.

`complete(task, system, prompt)`:
  1. cache hit? return it.
  2. otherwise walk the router's model chain for the task, consuming budget,
     trying each model until one returns a real (non-error) response.
  3. cache and return the first success; if all fail, return the last message.

The provider call is injected (`complete_fn`) so this is fully testable offline
and so the agent/service can share one orchestrator.
"""

import inspect
from typing import Awaitable, Callable, Optional

from spaf.orchestration.budget import Budget, BudgetExceeded
from spaf.orchestration.cache import ResponseCache, make_key
from spaf.orchestration.router import ModelRouter
from spaf.utils.logger import logger

# A provider response that starts with any of these is treated as a failure
# (the AI layer returns graceful error strings rather than raising).
_ERROR_PREFIXES = ("⚠️", "Error [")

CompleteFn = Callable[[str, str, Optional[str]], Awaitable[str]]  # (system, prompt, model) -> text


def _looks_like_error(text: str) -> bool:
    t = (text or "").lstrip()
    return not t or any(t.startswith(p) for p in _ERROR_PREFIXES)


class Orchestrator:
    def __init__(self, complete_fn: Optional[CompleteFn] = None,
                 provider: str = "", router: Optional[ModelRouter] = None,
                 cache: Optional[ResponseCache] = None):
        self.router = router or ModelRouter()
        self.cache = cache or ResponseCache()
        self.provider = provider or self._detect_provider()
        self._complete_fn = complete_fn or self._default_complete_fn()

    def _detect_provider(self) -> str:
        try:
            from spaf.utils.ai import ai_orchestrator
            return ai_orchestrator.provider
        except Exception:
            return "unknown"

    def _default_complete_fn(self) -> CompleteFn:
        from spaf.utils.ai import ai_orchestrator

        async def fn(system: str, prompt: str, model: Optional[str]) -> str:
            return await ai_orchestrator.complete(system, prompt, model=model)
        return fn

    async def _call(self, system: str, prompt: str, model: Optional[str]) -> str:
        res = self._complete_fn(system, prompt, model)
        if inspect.isawaitable(res):
            res = await res
        return res

    async def complete(self, task: str, system: str, prompt: str, *,
                       budget: Optional[Budget] = None, use_cache: bool = True) -> str:
        chain = self.router.resolve(task)
        last = ""
        for model in chain:
            key = make_key(self.provider, model or "default", system, prompt)
            if use_cache:
                cached = self.cache.get(key)
                if cached is not None:
                    return cached
            if budget is not None:
                try:
                    budget.consume(len(system) + len(prompt))
                except BudgetExceeded as exc:
                    logger.warning(f"orchestrator: {exc}")
                    return last or f"⚠️  {exc}"
            last = await self._call(system, prompt, model)
            if not _looks_like_error(last):
                if use_cache:
                    self.cache.set(key, last)
                return last
            logger.debug(f"orchestrator: model {model or 'default'} failed for task '{task}', trying next.")
        return last


_default: Optional[Orchestrator] = None


def default_orchestrator() -> Orchestrator:
    """Lazily-built shared orchestrator over the configured provider."""
    global _default
    if _default is None:
        _default = Orchestrator()
    return _default
