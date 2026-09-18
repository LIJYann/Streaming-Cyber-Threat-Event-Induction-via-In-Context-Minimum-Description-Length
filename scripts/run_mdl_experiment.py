#!/usr/bin/env python3
"""Minimal causal-LM MDL runner for the streaming benchmark.

Only a model-facing JSONL stream is accepted.  The runner never opens a
benchmark file and never uses labels, incident identifiers, or future rows.
At step ``t`` it retrieves the top-k lexical historical candidates, computes
the token-normalized code-length reduction

    ΔR(x; c) = L(x | empty) - L(x | c),

and emits the shared ``{id, label, target}`` prediction contract.  A local
Hugging Face causal LM can be loaded with ``--model-path``; loading is always
``local_files_only=True`` so a missing model cannot trigger a download.  The
``--mock`` scorer is a deterministic CPU smoke-test path and is not a model
result.

Examples::

    # Smoke test without a model download
    python3 scripts/run_mdl_experiment.py --stream data/model_input/synthetic_input_1000.jsonl \
        --output /tmp/mdl.jsonl --limit 100 --mock

    # Local model, CPU by default when CUDA is unavailable
    python3 scripts/run_mdl_experiment.py --stream data/model_input/synthetic_input_1000.jsonl \
        --output /tmp/mdl.jsonl --model-path /models/tiny-gpt2 --device cpu

    python3 scripts/evaluate.py --stream data/model_input/synthetic_input_1000.jsonl \
        --benchmark data/synthetic_benchmark_1000.jsonl --pred /tmp/mdl.jsonl
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import read_jsonl, tokenize  # noqa: E402


_CVE_RE = re.compile(r"\bCVE[-_ ]?\d{4}[-_]\d{4,7}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|co|info|biz|xyz)\b", re.IGNORECASE
)
_EVENT_CUE_RE = re.compile(
    r"\b(?:attack|attacker|backdoor|botnet|breach|campaign|c2|command and control|"
    r"compromise|credential|cyber|ddos|exploit|exfiltrat\w*|infect\w*|intrusion|"
    r"ioc|malware|malicious|payload|persistence|phishing|ransomware|scan(?:ning)?|"
    r"shellcode|threat|trojan|vulnerability|weaponiz\w*)\b",
    re.IGNORECASE,
)
_FORBIDDEN_FIELDS = frozenset(
    {
        "ground_truth_label",
        "ground_truth_label_name",
        "target_incident_id",
        "rationale",
        "doc_id",
        "incident_id",
        "campaign_id",
        "actor_id",
        "cves",
    }
)


def _text(row: Dict) -> str:
    title = row.get("title") or ""
    body = row.get("text") or row.get("content") or ""
    return f"{title}\n{body}" if title else body


def _observable_indicators(text: str) -> frozenset[str]:
    values: Set[str] = set()
    values.update(f"cve:{x.upper().replace('_', '-').replace(' ', '')}" for x in _CVE_RE.findall(text))
    values.update(f"ip:{x}" for x in _IP_RE.findall(text))
    values.update(f"hash:{x.lower()}" for x in _HASH_RE.findall(text))
    values.update(f"domain:{x.lower()}" for x in _DOMAIN_RE.findall(text))
    return frozenset(sorted(values))


def _event_like(text: str, indicators: frozenset[str]) -> bool:
    return bool(indicators or _EVENT_CUE_RE.search(text))


def _lexical_similarity(
    left_tokens: frozenset[str],
    right_tokens: frozenset[str],
    left_indicators: frozenset[str],
    right_indicators: frozenset[str],
) -> float:
    """Deterministic candidate-retrieval score, never used as a label oracle."""
    union = len(left_tokens | right_tokens)
    lexical = len(left_tokens & right_tokens) / union if union else 0.0
    indicator_union = len(left_indicators | right_indicators)
    indicator = (
        len(left_indicators & right_indicators) / indicator_union
        if indicator_union
        else 0.0
    )
    return 0.7 * lexical + 0.3 * indicator


class TokenScorer(Protocol):
    """Minimal scorer interface used by the streaming loop and smoke tests."""

    def score(self, context: str, target: str) -> float:
        """Return average negative log2 likelihood (bits per target token)."""


class MockScorer:
    """Deterministic CPU scorer for smoke tests; not a language-model result."""

    def score(self, context: str, target: str) -> float:
        target_tokens = frozenset(tokenize(target))
        context_tokens = frozenset(tokenize(context))
        if not target_tokens:
            return 0.0
        overlap = len(target_tokens & context_tokens)
        # The constant keeps empty-context scores nonzero.  Each repeated
        # observable token reduces code length by a deterministic amount.
        return 8.0 - 0.5 * overlap / len(target_tokens)


class LocalCausalScorer:
    """Hugging Face causal-LM scorer with strictly local loading."""

    def __init__(self, model_path: Path, device: str = "auto", max_length: int = 1024) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError("local scoring requires torch and transformers") from exc
        if not model_path.exists():
            raise FileNotFoundError(f"local model path does not exist: {model_path}")
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"
        if device == "cuda" and not torch.cuda.is_available():
            device = "cpu"
        self._torch = torch
        self.device = torch.device(device)
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(model_path), local_files_only=True
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            str(model_path), local_files_only=True
        ).to(self.device)
        self.model.eval()
        self.max_length = max(2, int(max_length))
        self.bos_id = (
            self.tokenizer.bos_token_id
            or self.tokenizer.cls_token_id
            or self.tokenizer.eos_token_id
        )

    def _ids(self, value: str) -> List[int]:
        return list(self.tokenizer(value, add_special_tokens=False)["input_ids"])

    def score(self, context: str, target: str) -> float:
        target_ids = self._ids(target)
        if not target_ids:
            return 0.0
        # Preserve a complete target whenever possible and truncate only the
        # left side of context to respect the local model's context window.
        target_ids = target_ids[: self.max_length - 1]
        prefix_ids = self._ids(context)
        if self.bos_id is not None:
            prefix_ids = [int(self.bos_id)] + prefix_ids
        prefix_budget = max(1, self.max_length - len(target_ids))
        prefix_ids = prefix_ids[-prefix_budget:]
        ids = prefix_ids + target_ids
        if len(ids) < 2:
            return 0.0
        input_ids = self._torch.tensor([ids], dtype=self._torch.long, device=self.device)
        with self._torch.inference_mode():
            logits = self.model(input_ids=input_ids).logits[0]
        # Token i is predicted by the logits at i-1.  The first target token
        # therefore starts at the final prefix position minus one.
        start = len(prefix_ids) - 1
        target_tensor = input_ids[0, len(prefix_ids) : len(prefix_ids) + len(target_ids)]
        selected = logits[start : start + len(target_ids)]
        log_probs = self._torch.log_softmax(selected, dim=-1)
        nll = -log_probs.gather(1, target_tensor.unsqueeze(1)).squeeze(1).mean()
        return float(nll.item() / math.log(2.0))


@dataclass(frozen=True)
class _History:
    doc_id: str
    text: str
    tokens: frozenset[str]
    indicators: frozenset[str]


def validate_model_input(rows: Sequence[Dict]) -> None:
    """Fail closed if a benchmark/GT field is present in the model input."""
    for index, row in enumerate(rows):
        if not isinstance(row.get("id"), str) or not row["id"]:
            raise ValueError(f"row {index} must have a non-empty string id")
        if not isinstance(row.get("publish_time"), str) or not row["publish_time"]:
            raise ValueError(f"row {index} must have publish_time")
        leaked = sorted(_FORBIDDEN_FIELDS.intersection(row))
        if leaked:
            raise ValueError(f"model-input row {index} contains forbidden fields: {leaked}")
        # Empty text is a valid model-facing representation of a NO_EVENT row;
        # it must be scored and emitted as a prediction rather than dropped.


def run_stream(
    rows: Sequence[Dict],
    scorer: TokenScorer,
    *,
    top_k: int = 4,
    same_delta_r: float = 0.10,
    related_delta_r: float = 0.02,
) -> Tuple[List[Dict], List[Dict]]:
    """Run online MDL and return predictions plus non-contract diagnostics."""
    if top_k < 1:
        raise ValueError("top_k must be positive")
    if related_delta_r > same_delta_r:
        raise ValueError("related_delta_r cannot exceed same_delta_r")
    validate_model_input(rows)
    history: List[_History] = []
    predictions: List[Dict] = []
    diagnostics: List[Dict] = []
    for row in rows:
        text = _text(row)
        current_tokens = frozenset(tokenize(text))
        current_indicators = _observable_indicators(text)
        is_event = _event_like(text, current_indicators)
        ranked = sorted(
            (
                _lexical_similarity(current_tokens, item.tokens, current_indicators, item.indicators),
                -index,
                item,
            )
            for index, item in enumerate(history)
        )
        candidates = [item for _, _, item in ranked[-top_k:]][::-1]
        empty_nll = scorer.score("", text)
        best = None
        for candidate in candidates:
            candidate_nll = scorer.score(candidate.text, text)
            delta_r = empty_nll - candidate_nll
            similarity = _lexical_similarity(
                current_tokens, candidate.tokens, current_indicators, candidate.indicators
            )
            record = (delta_r, similarity, candidate.doc_id, candidate_nll)
            if best is None or record[:3] > best[:3]:
                best = record

        label = "NO_EVENT"
        target: Optional[str] = None
        best_delta = 0.0 if best is None else best[0]
        best_similarity = 0.0 if best is None else best[1]
        if is_event:
            if best is not None and best_delta >= same_delta_r:
                label, target = "SAME_EVENT", best[2]
            elif best is not None and best_delta >= related_delta_r and best_similarity > 0:
                label = "RELATED_EVENT"
            else:
                label = "UNSEEN_EVENT"
        predictions.append({"id": row["id"], "label": label, "target": target})
        diagnostics.append(
            {
                "id": row["id"],
                "label": label,
                "target": target,
                "empty_nll_bits": round(empty_nll, 6),
                "best_delta_r_bits": round(best_delta, 6),
                "best_similarity": round(best_similarity, 6),
                "n_candidates": len(candidates),
            }
        )
        # State mutation happens only after the decision.
        if is_event:
            history.append(_History(row["id"], text, current_tokens, current_indicators))
    return predictions, diagnostics


def _write_jsonl(path: Path, rows: Iterable[Dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Online causal-LM MDL stream runner")
    parser.add_argument("--stream", required=True, type=Path, help="model-facing JSONL only")
    parser.add_argument("--output", required=True, type=Path, help="prediction JSONL")
    scorer_group = parser.add_mutually_exclusive_group(required=True)
    scorer_group.add_argument("--model-path", type=Path, help="local HF causal-LM directory")
    scorer_group.add_argument("--mock", action="store_true", help="deterministic smoke scorer")
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--max-length", type=int, default=1024)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--same-delta-r", type=float, default=0.10)
    parser.add_argument("--related-delta-r", type=float, default=0.02)
    parser.add_argument("--limit", type=int, help="process only the first N rows (smoke tests)")
    parser.add_argument("--diagnostics", type=Path, help="optional ΔR diagnostics JSONL")
    args = parser.parse_args(argv)
    rows = read_jsonl(args.stream)
    if args.limit is not None:
        if args.limit < 1:
            parser.error("--limit must be positive")
        rows = rows[: args.limit]
    if not rows:
        parser.error("empty stream")
    scorer: TokenScorer
    scorer_name: str
    if args.mock:
        scorer, scorer_name = MockScorer(), "mock"
    else:
        scorer, scorer_name = LocalCausalScorer(args.model_path, args.device, args.max_length), "local"
    predictions, diagnostics = run_stream(
        rows,
        scorer,
        top_k=args.top_k,
        same_delta_r=args.same_delta_r,
        related_delta_r=args.related_delta_r,
    )
    _write_jsonl(args.output, predictions)
    if args.diagnostics:
        _write_jsonl(args.diagnostics, diagnostics)
    print(
        json.dumps(
            {
                "scorer": scorer_name,
                "n_documents": len(rows),
                "output": str(args.output),
                "diagnostics": str(args.diagnostics) if args.diagnostics else None,
                "device": str(getattr(scorer, "device", "cpu")),
            },
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
