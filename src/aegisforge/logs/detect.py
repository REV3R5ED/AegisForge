"""Format auto-detection: sniff the first lines, pick the best parser.

Each parser scores the sample (fraction of non-blank lines it
recognizes); the highest scorer wins. The chosen parser name,
confidence, and per-parser scores are always reported so the choice
is auditable — never silent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegisforge.logs.models import PARSER_UNKNOWN, PARSERS
from aegisforge.logs.parsers import PARSER_CLASSES, BaseParser

#: Lines sampled for detection.
SAMPLE_LINES = 50

#: Minimum top score to accept a parser; below this the format is unknown.
MIN_CONFIDENCE = 0.4


@dataclass
class DetectionResult:
    parser: str = PARSER_UNKNOWN
    confidence: float = 0.0
    scores: dict[str, float] = field(default_factory=dict)
    lines_sampled: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "parser": self.parser,
            "confidence": round(self.confidence, 3),
            "scores": {k: round(v, 3) for k, v in self.scores.items()},
            "lines_sampled": self.lines_sampled,
        }


def detect_lines(lines: list[str], sample_size: int = SAMPLE_LINES) -> DetectionResult:
    """Detect the format of *lines* (already-read sample)."""
    sample = [ln for ln in lines if ln.strip()][:sample_size]
    result = DetectionResult(lines_sampled=len(sample))
    if not sample:
        return result
    instances: list[BaseParser] = [cls() for cls in PARSER_CLASSES]
    for parser in instances:
        hits = sum(1 for ln in sample if parser.matches(ln.rstrip("\n")))
        result.scores[parser.name] = hits / len(sample)
    best = max(instances, key=lambda p: result.scores[p.name])
    top = result.scores[best.name]
    if top >= MIN_CONFIDENCE:
        result.parser = best.name
        result.confidence = top
    return result


def detect_file(path: str, sample_size: int = SAMPLE_LINES) -> DetectionResult:
    """Detect the format of a log file by sniffing its first lines."""
    lines: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                lines.append(line)
            if len(lines) >= sample_size:
                break
    return detect_lines(lines, sample_size=sample_size)


def parser_names() -> list[str]:
    return list(PARSERS)
