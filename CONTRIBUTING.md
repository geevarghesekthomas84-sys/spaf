# Contributing to SPAF

Thanks for your interest in improving SPAF! This guide covers everything you need
to get a change merged.

## Ground rules

- **Authorized use only.** SPAF is an offensive-security framework. Only contribute
  features and test against systems you own or are explicitly authorized to test.
  See [SECURITY.md](SECURITY.md) and the Legal Disclaimer in the README.
- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/geevarghesekthomas84-sys/spaf
cd spaf
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # core + pytest
# optional extras:
pip install -e ".[ai,intel]"     # AI providers + Shodan
cp .env.example .env             # then fill in what you need
```

External recon binaries used by `spaf toolkit` (subfinder, httpx, nuclei, …) are
optional at runtime; check what you have with `spaf tools`.

## Before you open a PR

Run the same checks CI runs:

```bash
pytest -q                 # tests must pass
ruff check spaf tests     # lint (real-defect rules only — see pyproject.toml)
python -m build           # wheel must build with all subpackages
```

- **Add tests** for new behavior. Parsing/logic should be unit-testable without
  network access or external binaries (see `tests/test_toolkit.py` for the pattern
  of mocking `_available` / subprocess output).
- **Keep changes focused.** One logical change per PR.
- **Match the surrounding style.** The codebase favors readable column alignment;
  the linter is configured to allow it, so please don't reformat unrelated code.
- **Never weaken safety.** Pass external input to tools as argument lists (not shell
  strings), validate targets, and respect engagement scope.

## Adding a new scan module

1. Subclass `BaseModule` in `spaf/modules/`, implementing `run()` and
   `render_results()`.
2. Return findings via `build_finding(...)` from `spaf.utils.risk`.
3. Register it in the CLI (`spaf/cli/main.py`) as a new command and in the
   `watch` module map.
4. Document it in `README.md` and `COMMANDS.md`, and add tests.

## Commit messages

Use clear, imperative summaries (e.g. "Add katana crawler stage"). Explain the
*why* in the body when it isn't obvious.
