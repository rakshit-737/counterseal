"""Run the deterministic Phase 2 candidate-compilation smoke demo."""

from __future__ import annotations

import json

from counterseal.engine.offline_demo import run_candidate_matrix


def main() -> int:
    print(json.dumps(run_candidate_matrix().as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
