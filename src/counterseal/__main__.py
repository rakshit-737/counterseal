"""Allow python -m counterseal init-token in a source checkout."""

from .backend.cli import main

raise SystemExit(main())
