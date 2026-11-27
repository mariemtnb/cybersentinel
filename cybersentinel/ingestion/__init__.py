"""Source connectors. One module per source; each exposes `extract(...) -> SourceBatch`.

A connector does two separate things:
1. fetch — talk to the API and return the original JSON payloads, untouched;
2. parse — flatten those payloads into tables (pandas DataFrames).

Keeping them separate lets the pipeline save the original payloads in the raw layer before
anything is transformed, and lets the tests run `parse` on saved real responses without
network access.
"""
