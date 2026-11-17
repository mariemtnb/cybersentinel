"""Validate a table against its data contract and split it into valid and rejected rows.

Steps (the same idea as TP1/TP4, extended):
1. Structure  — every contract column must be present. A missing column means the source
                changed its schema: the whole table is blocked (critical).
2. Types      — each column is converted to its contract type. A value that cannot be
                converted (e.g. "2024-13-45" as a date) rejects that row, not the table.
3. Rules      — a Pandera schema built from the contract checks required fields, patterns
                (CVE-YYYY-NNNN…), allowed values and min/max ranges (scores between 0 and 10…).
4. Uniqueness — the primary key must be unique; later duplicates are rejected.
5. Thresholds — if the share of rejected rows exceeds the contract's `maxRejectRate`, or the
                table has fewer rows than `minRows`, the table is blocked (critical): something
                is wrong upstream, and loading a partial picture would mislead the dashboard.

Rejected rows are never dropped silently: they are returned with their reasons so the
pipeline can store them in the quarantine table and in the `rejected/` area of the lake.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd
import pandera.pandas as pa
from pandera.errors import SchemaErrors

from cybersentinel.validation.contracts import ColumnSpec, Contract

BOOL_MAP = {"true": True, "false": False, "1": True, "0": False, True: True, False: False}


@dataclass
class ValidationReport:
    table: str
    rows_in: int
    rows_valid: int
    rows_rejected: int
    reasons: dict[str, int] = field(default_factory=dict)
    critical: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.critical

    @property
    def reject_rate(self) -> float:
        return self.rows_rejected / self.rows_in if self.rows_in else 0.0


def _coerce(series: pd.Series, spec: ColumnSpec) -> pd.Series:
    t = spec.logical_type
    if t == "string":
        return series.astype("string").str.strip().replace("", pd.NA)
    if t == "integer":
        return pd.to_numeric(series, errors="coerce").astype("Int64")
    if t == "number":
        return pd.to_numeric(series, errors="coerce").astype("Float64")
    if t == "boolean":
        return series.map(
            lambda v: (
                BOOL_MAP.get(v if isinstance(v, bool) else str(v).lower(), pd.NA) if pd.notna(v) else pd.NA
            )
        ).astype("boolean")
    if t == "date":
        parsed = pd.to_datetime(series, errors="coerce", utc=True, format="ISO8601")
        return parsed.dt.tz_convert(None).dt.normalize()
    if t == "timestamp":
        return pd.to_datetime(series, errors="coerce", utc=True, format="ISO8601")
    raise ValueError(t)


def _bound(spec: ColumnSpec, value):
    if spec.logical_type == "date":
        return pd.Timestamp(value)
    if spec.logical_type == "timestamp":
        return pd.Timestamp(value, tz="UTC")
    return value


def build_schema(contract: Contract) -> pa.DataFrameSchema:
    columns = {}
    for spec in contract.columns:
        checks = []
        if spec.pattern:
            checks.append(
                pa.Check.str_matches(spec.pattern, error=f"{spec.name}: does not match {spec.pattern}")
            )
        if spec.minimum is not None:
            checks.append(
                pa.Check.ge(_bound(spec, spec.minimum), error=f"{spec.name}: below minimum {spec.minimum}")
            )
        if spec.maximum is not None:
            checks.append(
                pa.Check.le(_bound(spec, spec.maximum), error=f"{spec.name}: above maximum {spec.maximum}")
            )
        if spec.allowed_values:
            checks.append(pa.Check.isin(spec.allowed_values, error=f"{spec.name}: value not allowed"))
        columns[spec.name] = pa.Column(None, checks=checks, nullable=not spec.required, required=True)
    return pa.DataFrameSchema(columns, strict=False, name=contract.table)


def validate_table(
    df: pd.DataFrame, contract: Contract
) -> tuple[pd.DataFrame, pd.DataFrame, ValidationReport]:
    report = ValidationReport(contract.table, rows_in=len(df), rows_valid=0, rows_rejected=0)

    missing = [c for c in contract.column_names if c not in df.columns]
    if missing:
        report.critical.append(f"{contract.table}: columns missing compared with the contract: {missing}")
        return df.iloc[0:0], df.assign(_reject_reasons="schema_mismatch"), report
    extra = [c for c in df.columns if c not in contract.column_names]
    if extra:
        report.warnings.append(f"{contract.table}: columns not in the contract were dropped: {extra}")

    work = df[contract.column_names].reset_index(drop=True).copy()
    reasons: dict[int, list[str]] = {}

    def flag(index, reason: str) -> None:
        for i in index:
            reasons.setdefault(int(i), []).append(reason)

    # 2. types
    for spec in contract.columns:
        original = work[spec.name]
        converted = _coerce(original, spec)
        bad = original.notna() & converted.isna() & (original.astype("string").str.strip() != "")
        flag(work.index[bad], f"{spec.name}: not a valid {spec.logical_type}")
        work[spec.name] = converted

    # 3. rules (Pandera, lazy = collect every failure instead of stopping at the first)
    try:
        build_schema(contract).validate(work, lazy=True)
    except SchemaErrors as err:
        cases = err.failure_cases
        for _, case in cases.iterrows():
            idx = case.get("index")
            if pd.isna(idx):
                continue
            check = str(case.get("check"))
            col = case.get("column")
            reason = f"{col}: required value is missing" if "not_nullable" in check else check
            flag([idx], reason)

    # 4. uniqueness of the primary key (keep the first occurrence)
    if contract.primary_key:
        dup = work.duplicated(subset=contract.primary_key, keep="first")
        flag(work.index[dup], "duplicate primary key " + "+".join(contract.primary_key))
    for spec in contract.columns:
        if spec.unique and spec.name not in contract.primary_key:
            flag(
                work.index[work.duplicated(subset=[spec.name], keep="first") & work[spec.name].notna()],
                f"{spec.name}: duplicate value",
            )

    rejected_mask = work.index.isin(list(reasons))
    valid = work[~rejected_mask].reset_index(drop=True)
    rejected = df.reset_index(drop=True)[rejected_mask].copy()
    rejected["_reject_reasons"] = [";".join(dict.fromkeys(reasons[i])) for i in work.index[rejected_mask]]

    report.rows_valid, report.rows_rejected = len(valid), len(rejected)
    for text in rejected["_reject_reasons"]:
        for r in text.split(";"):
            report.reasons[r] = report.reasons.get(r, 0) + 1

    # 5. thresholds
    if report.rows_in and report.reject_rate > contract.max_reject_rate:
        report.critical.append(
            f"{contract.table}: reject rate {report.reject_rate:.1%} is above the contract limit "
            f"{contract.max_reject_rate:.1%} ({report.rows_rejected}/{report.rows_in} rows)"
        )
    if report.rows_valid < contract.min_rows:
        report.critical.append(
            f"{contract.table}: {report.rows_valid} valid rows, contract requires at least "
            f"{contract.min_rows}"
        )
    return valid, rejected, report
