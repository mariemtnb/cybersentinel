"""Raw layer: immutable, source-specific snapshots of what each API returned.

Layout (identical on local disk, MinIO and AWS S3):

    raw/<source>/ingest_date=YYYY-MM-DD/run_id=<run_id>/<payload>.json.gz   original API responses
    raw/<source>/ingest_date=YYYY-MM-DD/run_id=<run_id>/_manifest.json      request params, counts, hashes
    validated/<table>/ingest_date=.../run_id=.../data.parquet               rows that passed the contract
    rejected/<table>/ingest_date=.../run_id=.../data.parquet                rows that failed, with reasons

Files are only ever added, never overwritten or deleted, so any past run can be replayed or
audited. The backend is chosen with RAW_STORAGE=local|s3. With s3, S3_ENDPOINT_URL points at
MinIO locally; removing it targets AWS S3 — the code does not change.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Protocol

import pandas as pd

from cybersentinel.ingestion.base import RawPayload
from cybersentinel.logs import get_logger

log = get_logger("raw_store")


class ObjectWriter(Protocol):
    def put(self, key: str, data: bytes) -> str: ...
    def get(self, key: str) -> bytes: ...
    def list(self, prefix: str) -> list[str]: ...


class LocalWriter:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def put(self, key: str, data: bytes) -> str:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise FileExistsError(f"raw object already exists, refusing to overwrite: {path}")
        path.write_bytes(data)
        return str(path)

    def get(self, key: str) -> bytes:
        return (self.root / key).read_bytes()

    def list(self, prefix: str) -> list[str]:
        base = self.root / prefix
        if not base.exists():
            return []
        return sorted(
            str(p.relative_to(self.root)).replace("\\", "/") for p in base.rglob("*") if p.is_file()
        )


class S3Writer:
    def __init__(self, bucket: str, endpoint_url: str | None, region: str | None) -> None:
        import boto3  # imported lazily: only needed when RAW_STORAGE=s3

        self.bucket = bucket
        self.client = boto3.client("s3", endpoint_url=endpoint_url, region_name=region)
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        """Create the bucket on first use (local MinIO). On AWS the bucket is created by the
        deployment (Terraform/console) and this call only checks that it is reachable."""
        from botocore.exceptions import ClientError

        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchBucket"):
                self.client.create_bucket(Bucket=self.bucket)
            else:
                raise

    def put(self, key: str, data: bytes) -> str:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)
        return f"s3://{self.bucket}/{key}"

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def list(self, prefix: str) -> list[str]:
        keys, token = [], None
        while True:
            kwargs = {
                "Bucket": self.bucket,
                "Prefix": prefix,
                **({"ContinuationToken": token} if token else {}),
            }
            page = self.client.list_objects_v2(**kwargs)
            keys += [o["Key"] for o in page.get("Contents", [])]
            if not page.get("IsTruncated"):
                return keys
            token = page["NextContinuationToken"]


class RawStore:
    def __init__(self, writer: ObjectWriter) -> None:
        self.writer = writer

    @staticmethod
    def _partition(run_id: str, started_at: datetime) -> str:
        return f"ingest_date={started_at:%Y-%m-%d}/run_id={run_id}"

    def save_payloads(
        self, source: str, run_id: str, started_at: datetime, payloads: list[RawPayload], metadata: dict
    ) -> dict:
        prefix = f"raw/{source}/{self._partition(run_id, started_at)}"
        manifest = {
            "source": source,
            "run_id": run_id,
            "started_at": started_at.isoformat(),
            "metadata": metadata,
            "payloads": [],
        }
        total_bytes = 0
        for payload in payloads:
            data = json.dumps(payload.body, ensure_ascii=False).encode("utf-8")
            total_bytes += len(data)
            location = self.writer.put(f"{prefix}/{payload.name}.json.gz", gzip.compress(data))
            manifest["payloads"].append(
                {
                    "name": payload.name,
                    "location": location,
                    "request": payload.request,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        self.writer.put(
            f"{prefix}/_manifest.json", json.dumps(manifest, indent=2, default=str).encode("utf-8")
        )
        log.info(
            "raw payloads saved",
            extra={"source": source, "files": len(payloads), "bytes": total_bytes, "prefix": prefix},
        )
        return {"prefix": prefix, "files": len(payloads), "bytes": total_bytes}

    def save_table(
        self, area: str, table: str, run_id: str, started_at: datetime, df: pd.DataFrame
    ) -> str | None:
        if df is None or df.empty:
            return None
        buffer = io.BytesIO()
        df.to_parquet(buffer, index=False)
        return self.writer.put(
            f"{area}/{table}/{self._partition(run_id, started_at)}/data.parquet", buffer.getvalue()
        )

    def load_payloads(self, source: str, run_prefix: str) -> list[RawPayload]:
        """Replay helper: read back the original payloads of a past run."""
        manifest = json.loads(self.writer.get(f"{run_prefix}/_manifest.json"))
        payloads = []
        for item in manifest["payloads"]:
            key = f"{run_prefix}/{item['name']}.json.gz"
            payloads.append(
                RawPayload(
                    item["name"], json.loads(gzip.decompress(self.writer.get(key))), item.get("request", {})
                )
            )
        return payloads


def make_raw_store(settings) -> RawStore:
    if settings.raw_storage == "s3":
        if not settings.s3_bucket:
            raise ValueError("RAW_STORAGE=s3 requires S3_BUCKET")
        return RawStore(S3Writer(settings.s3_bucket, settings.s3_endpoint_url, settings.s3_region))
    return RawStore(LocalWriter(settings.lake_dir))
