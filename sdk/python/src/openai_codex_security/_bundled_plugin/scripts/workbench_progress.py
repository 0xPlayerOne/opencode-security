"""Progress transition helpers for the Codex Security workbench."""

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench.handoff import require_current_continuation
from workbench_constants import PHASES
from workbench_validation import require_uuid


def reportable_count(
    current_phase: str, requested_phase: str | None, count: int | None
) -> int | None:
    if count is None and requested_phase in PHASES[3:] and current_phase in PHASES[:3]:
        return 0
    return count


def update_progress(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    scan_context: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = now()
        scan = require_scan(connection, scan_id)
        if scan["status"] != "running":
            raise SystemExit("Only a running scan can update progress.")
        require_current_continuation(
            scan,
            args.claim_token,
            error_message="Scan updates are owned by another continuation.",
        )
        if args.deep_review_pass is not None and scan["mode"] != "deep":
            raise SystemExit("Only Deep Scan can record a deep review pass.")
        progress = connection.execute(
            "SELECT * FROM scan_progress WHERE scan_id = ?", (scan["id"],)
        ).fetchone()
        if args.phase is not None and PHASES.index(args.phase) < PHASES.index(scan["phase"]):
            raise SystemExit("Scan progress cannot move to an earlier phase.")
        next_phase = args.phase or scan["phase"]
        phase_changed = next_phase != scan["phase"]
        phase_total = 0 if phase_changed else progress["phase_items_total"]
        phase_completed = 0 if phase_changed else progress["phase_items_completed"]
        phase_unit = None if phase_changed else progress["phase_progress_unit"]
        if args.phase_items_total is not None:
            phase_total = args.phase_items_total
        if args.phase_items_completed is not None:
            phase_completed = args.phase_items_completed
        if args.phase_progress_unit is not None:
            phase_unit = args.phase_progress_unit
        if phase_completed > phase_total:
            raise SystemExit("Completed phase items cannot exceed total phase items.")
        if phase_total > 0 and phase_unit is None:
            raise SystemExit("Phase progress with a nonzero total requires a progress unit.")
        if not phase_changed:
            if (
                args.phase_items_total is not None
                and args.phase_items_total < progress["phase_items_total"]
            ):
                raise SystemExit("Phase item total cannot decrease within a phase.")
            if (
                args.phase_items_completed is not None
                and args.phase_items_completed < progress["phase_items_completed"]
            ):
                raise SystemExit("Completed phase items cannot decrease within a phase.")
            if (
                args.phase_progress_unit is not None
                and progress["phase_progress_unit"] is not None
                and args.phase_progress_unit != progress["phase_progress_unit"]
            ):
                raise SystemExit("Phase progress unit cannot change within a phase.")
        updates: list[str] = []
        values: list[Any] = []
        for column, value in (
            ("review_items_total", args.review_items_total),
            ("review_items_completed", args.review_items_completed),
            (
                "reportable_findings_count",
                reportable_count(scan["phase"], args.phase, args.reportable_findings_count),
            ),
            ("deep_review_pass", args.deep_review_pass),
        ):
            if value is not None:
                updates.append(f"{column} = ?")
                values.append(value)
        current_pass = progress["deep_review_pass"] or 0
        requested_pass = args.deep_review_pass or current_pass
        if requested_pass < current_pass:
            raise SystemExit("Deep Scan progress cannot move to an earlier review pass.")
        advancing_pass = requested_pass > current_pass
        if advancing_pass and args.review_items_completed != 0:
            raise SystemExit("A new Deep Scan review pass must start with zero completed items.")
        if not advancing_pass:
            if (
                args.review_items_total is not None
                and args.review_items_total < progress["review_items_total"]
            ):
                raise SystemExit("Review item total cannot decrease within a review pass.")
            if (
                args.review_items_completed is not None
                and args.review_items_completed < progress["review_items_completed"]
            ):
                raise SystemExit("Completed review items cannot decrease within a review pass.")
        total = args.review_items_total
        if total is None:
            total = progress["review_items_total"]
        completed = args.review_items_completed
        if completed is None:
            completed = progress["review_items_completed"]
        if completed > total:
            raise SystemExit("Completed review items cannot exceed total review items.")
        updated = connection.execute(
            """
            UPDATE scans
            SET phase = COALESCE(?, phase), updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (args.phase, timestamp, scan["id"]),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can update progress.")
        if updates:
            connection.execute(
                f"UPDATE scan_progress SET {', '.join(updates)}, updated_at = ? WHERE scan_id = ?",
                (*values, timestamp, scan["id"]),
            )
        else:
            connection.execute(
                "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                (timestamp, scan["id"]),
            )
        connection.execute(
            """
            UPDATE scan_progress
            SET phase_items_total = ?, phase_items_completed = ?,
                phase_progress_unit = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (phase_total, phase_completed, phase_unit, timestamp, scan["id"]),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, scan["id"])


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
