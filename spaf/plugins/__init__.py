"""
SPAF plugin SDK.

Third parties extend SPAF by registering scan modules — either via a decorator
in a module SPAF imports, or (preferred for distribution) via a packaging
entry point in the ``spaf.modules`` group:

    # pyproject.toml of your plugin package
    [project.entry-points."spaf.modules"]
    myscan = "my_pkg.module:MyScanModule"

A plugin module subclasses ``PluginModule`` (an alias of the engine's
``BaseModule``) and implements ``run`` / ``render_results`` like the built-ins.

Registered modules become runnable through the CLI, service, API, and MCP. They
are **not** added to the autonomous agent's fixed action set — that stays a
curated, safety-reviewed list by design.
"""

from typing import Any, Callable, Dict, Optional

from spaf.core.engine import BaseModule
from spaf.utils.logger import logger

# A plugin module is just a BaseModule subclass.
PluginModule = BaseModule

_REGISTRY: Dict[str, type] = {}
_discovered = False


def register_module(name: str, cls: type) -> None:
    """Register a scan module under a CLI/service name (lowercased)."""
    name = name.strip().lower()
    if not name:
        raise ValueError("plugin module name must be non-empty")
    if not (isinstance(cls, type) and issubclass(cls, BaseModule)):
        raise TypeError(f"{cls!r} is not a BaseModule subclass")
    if name in _REGISTRY and _REGISTRY[name] is not cls:
        logger.warning(f"plugin: '{name}' is already registered; overriding.")
    _REGISTRY[name] = cls


def spaf_module(name: str) -> Callable[[type], type]:
    """Decorator form: ``@spaf_module("myscan")`` on a BaseModule subclass."""
    def deco(cls: type) -> type:
        register_module(name, cls)
        return cls
    return deco


def registered_modules() -> Dict[str, type]:
    """All registered plugin modules (after discovery)."""
    discover()
    return dict(_REGISTRY)


def get_module(name: str) -> Optional[type]:
    discover()
    return _REGISTRY.get(name.strip().lower())


def discover(force: bool = False) -> None:
    """Load plugins advertised via the ``spaf.modules`` entry-point group."""
    global _discovered
    if _discovered and not force:
        return
    _discovered = True
    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        group = eps.select(group="spaf.modules") if hasattr(eps, "select") else eps.get("spaf.modules", [])
        for ep in group:
            try:
                cls = ep.load()
                register_module(ep.name, cls)
                logger.info(f"plugin: loaded '{ep.name}' from {ep.value}")
            except Exception as exc:  # noqa: BLE001 - one bad plugin shouldn't break SPAF
                logger.error(f"plugin: failed to load '{ep.name}': {exc}")
    except Exception as exc:  # pragma: no cover
        logger.debug(f"plugin discovery skipped: {exc}")


__all__ = [
    "PluginModule", "register_module", "spaf_module",
    "registered_modules", "get_module", "discover",
]
