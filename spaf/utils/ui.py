"""
SPAF terminal design system.

One accent (molten amber) on a steel monochrome base. Severity colors are
reserved strictly for findings. Everything here is centralized so the whole CLI
reads as one instrument: the lockup, the wordmark, panels, rules and tables.
"""

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ── Palette ────────────────────────────────────────────────────────────────
AMBER = "#E0A82E"   # the one signature accent — the mark, key figures
AMBER_SOFT = "#C9972B"
STEEL = "#9AA0A6"   # secondary text, headers
FAINT = "#5C6370"   # tertiary / dividers / hints
OK = "#30A46C"
DANGER = "#E5484D"

# Severity is information, not decoration — a fixed, semantic ramp.
SEVERITY = {
    "Critical": "#E5484D",
    "High":     "#F0883E",
    "Medium":   "#E0A82E",
    "Low":      "#3FA7E0",
    "Info":     "#6B7280",
}

PANEL_BOX = box.ROUNDED
TABLE_BOX = box.SIMPLE

# ── Wordmark ───────────────────────────────────────────────────────────────
_WORDMARK = r"""███████╗██████╗  █████╗ ███████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝
███████╗██████╔╝███████║█████╗
╚════██║██╔═══╝ ██╔══██║██╔══╝
███████║██║     ██║  ██║██║
╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝"""


def severity_text(sev: str) -> Text:
    """A severity label in its semantic color."""
    return Text(sev, style=f"bold {SEVERITY.get(sev, FAINT)}")


def lockup(version: str, online: bool) -> Text:
    """The one-line identity reused across commands."""
    dot = OK if online else AMBER
    state = "online" if online else "offline"
    t = Text()
    t.append("◇ ", style=f"bold {AMBER}")
    t.append("SPAF", style=f"bold {AMBER}")
    t.append("  ·  ", style=FAINT)
    t.append("red-team automation", style=STEEL)
    t.append("  ·  ", style=FAINT)
    t.append(f"v{version}", style=STEEL)
    t.append("  ·  ", style=FAINT)
    t.append("● ", style=dot)
    t.append(state, style=STEEL)
    return t


def banner(version: str, online: bool, compact: bool = False) -> Group:
    """Full brand banner. `compact` drops the wordmark for sub-commands."""
    pieces = [Rule(style=FAINT)]
    if not compact:
        pieces.append(Text(_WORDMARK, style=f"bold {AMBER}"))
        pieces.append(Text())  # spacer
    pieces.append(lockup(version, online))
    pieces.append(Rule(style=FAINT))
    return Group(*pieces)


def eyebrow(label: str) -> Rule:
    """A section header rule with a steel, letter-spaced label."""
    spaced = " ".join(label.upper())
    return Rule(Text(f" {spaced} ", style=f"bold {STEEL}"), style=FAINT, align="left")


def panel(body, title: str = None, tone: str = AMBER, subtitle: str = None):
    return Panel(
        body,
        title=(Text(title, style=f"bold {tone}") if title else None),
        subtitle=(Text(subtitle, style=FAINT) if subtitle else None),
        border_style=tone,
        box=PANEL_BOX,
        padding=(1, 2),
    )


def fit_panel(body, tone: str = AMBER):
    return Panel.fit(body, border_style=tone, box=PANEL_BOX, padding=(1, 3))


def table(title: str = None) -> Table:
    """A table in the house style: hairline rules, steel uppercase headers."""
    return Table(
        title=(Text(title, style=f"bold {AMBER}") if title else None),
        box=TABLE_BOX,
        header_style=f"bold {STEEL}",
        border_style=FAINT,
        title_justify="left",
        pad_edge=False,
        expand=False,
    )


def kv(pairs, title: str = None, tone: str = AMBER):
    """A key/value summary rendered as a borderless grid inside a panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=STEEL, justify="right")
    grid.add_column(style="default")
    for k, v in pairs:
        grid.add_row(k, v)
    return panel(grid, title=title, tone=tone)
