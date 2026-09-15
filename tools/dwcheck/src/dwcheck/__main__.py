"""Allow `python -m dwcheck`, so the checks run without an installed script."""

from __future__ import annotations

from dwcheck.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
