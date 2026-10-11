# Contributing

    git clone <repo> && cd sentinel
    python3 -m venv .venv && . .venv/bin/activate
    pip install -e ".[ml,dev]"
    PYTHONPATH=tests python -m unittest discover -s tests
    ruff check src tests

- One focused change per pull request, with tests. The suite runs on a fake filesystem root, never on the real system.
- **New audit check:** add a function `run(cfg) -> list[Finding]` (see `src/sentinel/audit/`), decorate it with `@register("name")`
  and add tests using `tests/helpers.py`. Checks must be read-only and must not crash on missing files.
- **Database changes:** append a new entry to `MIGRATIONS` in `db.py`; never edit an existing one.
- Be kind - see CODE_OF_CONDUCT (Contributor Covenant 2.1 to be added before publishing).
