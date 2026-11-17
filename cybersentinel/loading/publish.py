"""PUBLISH step of write-audit-publish.

The pipeline writes into a working warehouse file. Only after dbt build and every dbt test
passed is that file copied to the published location, which is the only file the dashboard
reads. The copy goes to a temporary file in the same directory and is then renamed over the
old one: a rename is atomic, so readers see either the old complete version or the new
complete version — never a half-written database.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import duckdb

from cybersentinel.logs import get_logger

log = get_logger("publish")


def publish(working: Path, published: Path, attempts: int = 10) -> None:
    working, published = Path(working), Path(published)
    published.parent.mkdir(parents=True, exist_ok=True)
    # Merge the write-ahead log into the main file so the copy is self-contained.
    con = duckdb.connect(str(working))
    con.execute("CHECKPOINT")
    con.close()
    tmp = published.with_suffix(".duckdb.tmp")
    shutil.copyfile(working, tmp)
    for attempt in range(1, attempts + 1):
        try:
            os.replace(tmp, published)
            break
        except PermissionError:  # Windows only: a reader holds the file open; retry shortly
            if attempt == attempts:
                tmp.unlink(missing_ok=True)
                raise
            time.sleep(0.5 * attempt)
    log.info("warehouse published", extra={"path": str(published), "bytes": published.stat().st_size})
