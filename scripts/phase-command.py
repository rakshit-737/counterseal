"""Explicit non-implementations for future phase Make targets."""

from __future__ import annotations

import sys

SUPPORTED_PLACEHOLDERS = {"demo", "test-kind", "verify-bundle", "eval-offline"}


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    target = arguments[0] if arguments else "requested phase command"
    if target not in SUPPORTED_PLACEHOLDERS:
        print(f"{target}: NOT_IMPLEMENTED", file=sys.stderr)
        return 2
    print(f"{target}: NOT_IMPLEMENTED", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
