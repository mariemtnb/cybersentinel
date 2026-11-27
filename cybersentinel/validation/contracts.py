"""Read a data contract (ODCS v3 YAML in contracts/) into a small Python object.

The contract is the single source of truth for a table's columns, types, nullability,
uniqueness, patterns and value ranges. The validator (validate.py) and the CI job
(`datacontract test`) both read the same file, so the rules cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_TYPES = {"string", "integer", "number", "boolean", "date", "timestamp"}


class ContractError(ValueError):
    pass


@dataclass
class ColumnSpec:
    name: str
    logical_type: str
    required: bool = False
    unique: bool = False
    pattern: str | None = None
    minimum: Any = None
    maximum: Any = None
    allowed_values: list[Any] | None = None


@dataclass
class Contract:
    id: str
    table: str
    columns: list[ColumnSpec]
    primary_key: list[str] = field(default_factory=list)
    max_reject_rate: float = 0.0
    min_rows: int = 0
    version: str = "0"

    @property
    def column_names(self) -> list[str]:
        return [c.name for c in self.columns]


def _custom(props: list[dict] | None) -> dict[str, Any]:
    return {p["property"]: p.get("value") for p in props or [] if "property" in p}


def load_contract(path: Path) -> Contract:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("kind") != "DataContract":
        raise ContractError(f"{path}: not an ODCS DataContract")
    schema = doc.get("schema") or []
    if len(schema) != 1:
        raise ContractError(f"{path}: expected exactly one schema object, found {len(schema)}")
    obj = schema[0]
    columns = []
    for prop in obj.get("properties") or []:
        ltype = prop.get("logicalType")
        # ODCS v3 has no "timestamp" logical type: a timestamp is a `date` whose physical type is
        # timestamp. We keep the distinction because timestamps are parsed as UTC date-times.
        if ltype == "date" and str(prop.get("physicalType", "")).lower() in ("timestamp", "timestamptz"):
            ltype = "timestamp"
        if ltype not in SUPPORTED_TYPES:
            raise ContractError(f"{path}: column {prop.get('name')} has unsupported logicalType {ltype}")
        options = prop.get("logicalTypeOptions") or {}
        columns.append(
            ColumnSpec(
                name=prop["name"],
                logical_type=ltype,
                required=bool(prop.get("required")),
                unique=bool(prop.get("unique")),
                pattern=options.get("pattern"),
                minimum=options.get("minimum"),
                maximum=options.get("maximum"),
                allowed_values=_custom(prop.get("customProperties")).get("allowedValues"),
            )
        )
    custom = _custom(doc.get("customProperties"))
    return Contract(
        id=doc["id"],
        table=obj["name"],
        columns=columns,
        primary_key=list(custom.get("primaryKey") or []),
        max_reject_rate=float(custom.get("maxRejectRate", 0.0)),
        min_rows=int(custom.get("minRows", 0)),
        version=str(doc.get("version")),
    )


def load_all(contracts_dir: Path) -> dict[str, Contract]:
    contracts = {}
    for path in sorted(Path(contracts_dir).glob("*.yaml")):
        contract = load_contract(path)
        contracts[contract.table] = contract
    return contracts
