#!/usr/bin/env python3
"""CPU-only, deterministic online baseline for the CTI stream.

The predictor deliberately consumes only a model-facing JSONL projection.  It
never opens a benchmark file and never uses labels, incident ids, or future
documents.  At each step it compares the current document with the historical
memory using online TF-IDF and surface indicators (CVE, IP, domain, and hash).

Example::

    python3 scripts/deterministic_baseline.py \
        --stream data/model_input/misp_sliced_input_notitle.jsonl \
        --output predictions.jsonl
    python3 scripts/evaluate.py \
        --stream data/model_input/misp_sliced_input_notitle.jsonl \
        --benchmark data/misp_sliced_benchmark.jsonl --pred predictions.jsonl

The output follows ``scripts/evaluate.py``'s prediction contract.  SAME
targets are always ids of earlier rows in the input stream.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import normalize_text, read_jsonl, tokenize  # noqa: E402


# These are observable lexical features, not labels or benchmark metadata.
_CVE_RE = re.compile(r"\bCVE[-_ ]?\d{4}[-_]\d{4,7}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|co|info|biz|xyz)\b", re.IGNORECASE)
_EVENT_CUE_RE = re.compile(
    r"\b(?:attack|attacker|backdoor|botnet|breach|campaign|c2|command and control|"
    r"compromise|credential|cyber|ddos|exploit|exfiltrat\w*|infect\w*|intrusion|"
    r"ioc|malware|malicious|payload|persistence|phishing|ransomware|scan(?:ning)?|"
    r"shellcode|threat|trojan|vulnerability|weaponiz\w*)\b",
    re.IGNORECASE,
)

# Boilerplate dominates CTI projections.  Removing it makes the lexical score
# a useful strict historical baseline while retaining all raw text for output.
_STOPWORDS = frozenset(
    "a an and are as at by for from has have in into is it its of on or that the "
    "this to was were with after before report reports activity data document "
    "network other sample samples links link records record analyst notes note "
    "example examples e.g".split()
)


def _field(row: Dict) -> str:
    title = row.get("title") or ""
    text = row.get("text") or row.get("content") or ""
    return f"{title}\n{text}" if title else text


def _indicators(text: str) -> frozenset[str]:
    """Extract observable IOC-like strings with stable canonical forms."""
    out: Set[str] = set()
    out.update(f"cve:{m.upper().replace('_', '-').replace(' ', '')}" for m in _CVE_RE.findall(text))
    out.update(f"ip:{m}" for m in _IP_RE.findall(text))
    out.update(f"hash:{m.lower()}" for m in _HASH_RE.findall(text))
    out.update(f"domain:{m.lower()}" for m in _DOMAIN_RE.findall(text))
    return frozenset(sorted(out))


def _tokens(text: str) -> frozenset[str]:
    return frozenset(t for t in tokenize(text) if t not in _STOPWORDS and len(t) >= 3)


def _cosine(left: frozenset[str], right: frozenset[str], df: Counter, n_docs: int) -> float:
    if not left or not right:
        return 0.0
    # Binary TF-IDF is intentional: the input projection contains truncated
    # counts ("N records"), which should not dominate the comparison.
    def weight(token: str) -> float:
        return math.log((1.0 + n_docs) / (1.0 + df[token])) + 1.0

    common = left & right
    dot = sum(weight(token) ** 2 for token in common)
    left_norm = sum(weight(token) ** 2 for token in left)
    right_norm = sum(weight(token) ** 2 for token in right)
    return dot / math.sqrt(left_norm * right_norm) if left_norm and right_norm else 0.0


@dataclass(frozen=True)
class _MemoryDoc:
    doc_id: str
    timestamp: datetime
    tokens: frozenset[str]
    indicators: frozenset[str]
    event_like: bool


def _parse_time(row: Dict) -> datetime:
    value = row.get("publish_time")
    if not isinstance(value, str) or not value:
        raise ValueError(f"row {row.get('id', '<unknown>')} has no publish_time")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def _event_like(text: str, indicators: frozenset[str]) -> bool:
    return bool(indicators or _EVENT_CUE_RE.search(text))


def predict(
    rows: Sequence[Dict],
    *,
    same_threshold: float = 0.72,
    related_threshold: float = 0.28,
    same_window_days: float = 14.0,
) -> List[Dict]:
    """Predict a stream using only current and historical model-side fields."""
    if not 0 <= related_threshold <= same_threshold <= 1:
        raise ValueError("thresholds must satisfy 0 <= related <= same <= 1")
    memory: List[_MemoryDoc] = []
    df: Counter = Counter()
    token_index: Dict[str, Set[int]] = {}
    indicator_index: Dict[str, Set[int]] = {}
    predictions: List[Dict] = []
    same_window = timedelta(days=same_window_days)

    for row in rows:
        doc_id = row.get("id")
        if not isinstance(doc_id, str) or not doc_id:
            raise ValueError("every stream row needs a non-empty string id")
        text = _field(row)
        timestamp = _parse_time(row)
        current_tokens = _tokens(text)
        current_indicators = _indicators(text)
        current_event_like = _event_like(text, current_indicators)

        best: Optional[Tuple[float, int, _MemoryDoc, int]] = None
        # A zero-overlap TF-IDF score cannot beat either threshold.  The
        # inverted indexes preserve the exact historical-only semantics while
        # avoiding an O(T^2) scan on the released streams.
        candidate_indices: Set[int] = set()
        for token in current_tokens:
            candidate_indices.update(token_index.get(token, ()))
        for indicator in current_indicators:
            candidate_indices.update(indicator_index.get(indicator, ()))
        for index in sorted(candidate_indices):
            previous = memory[index]
            cosine = _cosine(current_tokens, previous.tokens, df, len(memory))
            shared = len(current_indicators & previous.indicators)
            # Exact indicator reuse is stronger than a generic lexical overlap.
            indicator_ratio = shared / max(1, min(len(current_indicators), len(previous.indicators)))
            same_window_hit = abs(timestamp - previous.timestamp) <= same_window
            same_score = cosine
            if shared:
                same_score = max(same_score, 0.55 + 0.1 * min(indicator_ratio, 1.0))
            rank = (same_score, shared, -index)
            if same_window_hit and (best is None or rank > (best[0], best[3], -best[1])):
                best = (same_score, index, previous, shared)

        label = "NO_EVENT"
        target: Optional[str] = None
        if current_event_like:
            same_candidate = best and best[0] >= same_threshold
            if same_candidate:
                label = "SAME_EVENT"
                target = best[2].doc_id
            else:
                # Relatedness can be established by an old indicator even when
                # the short-term lexical match is below the SAME threshold.
                related = any(indicator_index.get(indicator) for indicator in current_indicators)
                related = related or (best is not None and best[0] >= related_threshold)
                label = "RELATED_EVENT" if related else "UNSEEN_EVENT"

        predictions.append({"id": doc_id, "label": label, "target": target})

        # Register only event-like observations.  This keeps obvious noise from
        # becoming a future lexical/IOC anchor, while preserving online state.
        if current_event_like:
            memory_index = len(memory)
            memory.append(_MemoryDoc(doc_id, timestamp, current_tokens, current_indicators, True))
            df.update(current_tokens)
            for token in current_tokens:
                token_index.setdefault(token, set()).add(memory_index)
            for indicator in current_indicators:
                indicator_index.setdefault(indicator, set()).add(memory_index)
    return predictions


def validate_predictions(stream_rows: Sequence[Dict], predictions: Sequence[Dict]) -> None:
    """Reject malformed output, especially targets that point to the future."""
    if len(stream_rows) != len(predictions):
        raise ValueError("prediction count does not match stream count")
    seen: Set[str] = set()
    allowed = {"NO_EVENT", "SAME_EVENT", "RELATED_EVENT", "UNSEEN_EVENT"}
    for row, prediction in zip(stream_rows, predictions):
        if prediction.get("id") != row.get("id"):
            raise ValueError("prediction ids must preserve stream order")
        label = prediction.get("label")
        if label not in allowed:
            raise ValueError(f"invalid prediction label: {label!r}")
        target = prediction.get("target")
        if label == "SAME_EVENT":
            if not isinstance(target, str) or target not in seen:
                raise ValueError("SAME_EVENT target must refer to an earlier document")
        elif target is not None:
            raise ValueError("only SAME_EVENT predictions may have a target")
        seen.add(row["id"])


def _write_jsonl(path: Path, rows: Iterable[Dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic historical lexical/IOC baseline")
    parser.add_argument("--stream", required=True, type=Path, help="model-facing input JSONL")
    parser.add_argument("--output", required=True, type=Path, help="prediction JSONL")
    parser.add_argument("--same-threshold", type=float, default=0.72)
    parser.add_argument("--related-threshold", type=float, default=0.28)
    parser.add_argument("--same-window-days", type=float, default=14.0)
    args = parser.parse_args(argv)
    rows = read_jsonl(args.stream)
    if not rows:
        parser.error("empty stream")
    predictions = predict(
        rows,
        same_threshold=args.same_threshold,
        related_threshold=args.related_threshold,
        same_window_days=args.same_window_days,
    )
    validate_predictions(rows, predictions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_jsonl(args.output, predictions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
