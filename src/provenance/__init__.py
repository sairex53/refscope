"""Reference provenance schema and conservative evidence resolution."""

from .adapters import (
    AdapterReport, adapt_btf_kfunc_metadata, adapt_native_tracepoint_record,
    adapt_ref_tracker_records, discover_native_tracepoints, resolve_adapter_claims,
)
from .model import (
    SCHEMA_VERSION, Confidence, EvidenceClaim, EvidenceResolution, EvidenceSource,
    ReferenceEvent, ReferenceEvidence, downgrade_confidence, pair_reference_events,
    resolve_claims,
)

__all__ = [
    "SCHEMA_VERSION", "Confidence", "EvidenceClaim", "EvidenceResolution",
    "EvidenceSource", "ReferenceEvent", "ReferenceEvidence",
    "AdapterReport", "adapt_btf_kfunc_metadata", "adapt_native_tracepoint_record",
    "adapt_ref_tracker_records", "discover_native_tracepoints", "resolve_adapter_claims",
    "downgrade_confidence", "pair_reference_events", "resolve_claims",
]
