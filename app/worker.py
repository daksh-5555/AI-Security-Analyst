"""Background analysis worker entry point: ``python -m app.worker``.

Options:

- ``--once``: recover stale runs, execute at most one queued run, then exit.
- ``--recover-only``: run the stale-lease recovery sweep once and exit (useful
  as a periodic job when only synchronous runs are used).

The worker uses the same configuration and database as the API and refuses to
start with an insecure configuration, exactly like the API process.
"""

from __future__ import annotations

import argparse
import logging
import signal
import threading
from collections.abc import Sequence

from app.core.config import settings, validate_security_configuration
from app.db.session import engine
from app.services.analysis_worker import AnalysisWorker, recover_stale_runs

logger = logging.getLogger("app.worker")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.worker", description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="execute at most one run")
    mode.add_argument("--recover-only", action="store_true", help="recover stale runs only")
    args = parser.parse_args(argv)

    validate_security_configuration(settings)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.recover_only:
        summary = recover_stale_runs(engine)
        logger.info(
            "Recovery: %d requeued, %d failed, %d cancelled",
            len(summary.requeued),
            len(summary.failed),
            len(summary.cancelled),
        )
        return 0

    worker = AnalysisWorker(engine)
    if args.once:
        worker.run_once()
        return 0

    stop_event = threading.Event()

    def _stop(signum: int, _frame: object) -> None:
        logger.info("Signal %d received; finishing the current run, then stopping", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    worker.run_forever(stop_event)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a module entry point
    raise SystemExit(main())
