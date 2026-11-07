"""
Scoring engine for the AI Forensic Tool Evaluation Framework.

Each score_* function maps one raw metric to a 0-25 point sub-score using the
Table 1 rubric bands. compute_total_score() combines the sub-scores with a
weighting scheme, and validate_tool_spec() rejects missing or invalid input
before any scoring happens (test T9).

Keeping these as small, pure functions (no Streamlit, no I/O) means they can
be unit tested directly - these are the T1/T2 and T9 test cases from the
testing plan.
"""

# NOTE: each function returns one representative score per band (25/20/15/8).
# The paper's Table 1 gives point ranges (e.g. 23-25); the midpoint-style
# simplification is used so scores are deterministic and unit-testable.


def score_detection_accuracy(f1_score: float) -> float:
    """F1 score (0-1) -> 0-25 pts. Matches Table 1 exactly."""
    if f1_score > 0.95:
        return 25
    elif f1_score >= 0.90:
        return 20
    elif f1_score >= 0.80:
        return 15
    else:
        return 8


def score_false_positive_rate(fpr: float) -> float:
    """False positive rate as a fraction (0.02 = 2%). Matches Table 1 exactly."""
    if fpr < 0.01:
        return 25
    elif fpr <= 0.03:
        return 20
    elif fpr <= 0.05:
        return 15
    else:
        return 8


def score_overhead(latency_ms: float) -> float:
    """Inference latency in ms. Matches Table 1 exactly."""
    if latency_ms < 10:
        return 25
    elif latency_ms <= 50:
        return 20
    elif latency_ms <= 100:
        return 15
    else:
        return 8


def score_attack_coverage(categories_covered: int, total_categories: int = 4) -> float:
    """
    Count of MITRE ATT&CK categories covered (network, malware,
    reconnaissance, credential = 4 total per Table 1), mapped to 0-25 pts.
    """
    if categories_covered >= 4:
        return 25
    elif categories_covered == 3:
        return 20
    elif categories_covered == 2:
        return 15
    else:
        return 8


DEFAULT_WEIGHTS = {"accuracy": 0.25, "fpr": 0.25, "overhead": 0.25, "coverage": 0.25}

# Presets matching the T6 sensitivity-analysis test cases
WEIGHT_PRESETS = {
    "Equal (25/25/25/25)": DEFAULT_WEIGHTS,
    "Accuracy-priority (40%)": {"accuracy": 0.40, "fpr": 0.20, "overhead": 0.20, "coverage": 0.20},
    "FPR-priority (40%)": {"accuracy": 0.20, "fpr": 0.40, "overhead": 0.20, "coverage": 0.20},
}

REQUIRED_FIELDS = ("name", "f1_score", "fpr", "latency_ms", "categories_covered")


def validate_tool_spec(spec) -> list:
    """
    T9: check one tool specification before scoring.
    Returns a list of problems; an empty list means the spec is valid.
    Never raises, so the caller can show the problems instead of crashing.
    """
    if not isinstance(spec, dict):
        return ["specification is not an object"]

    errors = [f"missing field: {k}" for k in REQUIRED_FIELDS if spec.get(k) is None]
    if errors:
        return errors

    def is_number(x):
        return isinstance(x, (int, float)) and not isinstance(x, bool)

    if not isinstance(spec["name"], str) or not spec["name"].strip():
        errors.append("name must be non-empty text")
    if not is_number(spec["f1_score"]) or not 0 <= spec["f1_score"] <= 1:
        errors.append("f1_score must be a number between 0 and 1")
    if not is_number(spec["fpr"]) or not 0 <= spec["fpr"] <= 1:
        errors.append("fpr must be a number between 0 and 1")
    if not is_number(spec["latency_ms"]) or spec["latency_ms"] < 0:
        errors.append("latency_ms must be a non-negative number")

    total = spec.get("total_categories", 4)
    if isinstance(total, bool) or not isinstance(total, int) or total < 1:
        errors.append("total_categories must be a positive whole number")
        total = 4  # fall back so the next check can still run
    covered = spec["categories_covered"]
    if isinstance(covered, bool) or not isinstance(covered, int) or not 0 <= covered <= total:
        errors.append(f"categories_covered must be a whole number from 0 to {total}")

    return errors


def compute_total_score(tool_spec: dict, weights: dict = None) -> dict:
    """
    tool_spec needs: name, f1_score, fpr, latency_ms, categories_covered
      (optionally total_categories, defaults to 4).
    weights: dict with accuracy/fpr/overhead/coverage fractions summing to 1.0.
    Returns sub-scores (each already 0-25) and a total scaled to 0-100.
    Raises ValueError if the specification is missing fields or has invalid values.
    """
    errors = validate_tool_spec(tool_spec)
    if errors:
        raise ValueError("; ".join(errors))

    if weights is None:
        weights = DEFAULT_WEIGHTS

    sub_scores = {
        "accuracy": score_detection_accuracy(tool_spec["f1_score"]),
        "fpr": score_false_positive_rate(tool_spec["fpr"]),
        "overhead": score_overhead(tool_spec["latency_ms"]),
        "coverage": score_attack_coverage(
            tool_spec["categories_covered"], tool_spec.get("total_categories", 4)
        ),
    }
    # each sub-score is out of 25 at equal weight (0.25); rescale by weight/0.25
    total = sum(sub_scores[m] * (weights[m] / 0.25) for m in sub_scores)
    return {"sub_scores": sub_scores, "total": round(min(total, 100), 1)}


if __name__ == "__main__":
    # Quick manual sanity check - T1/T2 style. Run: python scoring.py
    sample = {"name": "Sample", "f1_score": 0.93, "fpr": 0.02, "latency_ms": 40, "categories_covered": 3}
    print("Equal weights:", compute_total_score(sample))
    print("Accuracy-priority:", compute_total_score(sample, WEIGHT_PRESETS["Accuracy-priority (40%)"]))

    # T1: band boundaries (Table 1: F1 > 0.95 is the top band, so exactly 0.95
    # falls in 0.90-0.95; FPR < 1% is the top band, so exactly 1% falls in 1-3%)
    assert score_detection_accuracy(0.951) == 25
    assert score_detection_accuracy(0.95) == 20
    assert score_detection_accuracy(0.90) == 20
    assert score_detection_accuracy(0.899) == 15
    assert score_detection_accuracy(0.80) == 15
    assert score_detection_accuracy(0.799) == 8
    assert score_false_positive_rate(0.0099) == 25
    assert score_false_positive_rate(0.01) == 20
    assert score_false_positive_rate(0.03) == 20
    assert score_false_positive_rate(0.031) == 15
    assert score_false_positive_rate(0.05) == 15
    assert score_false_positive_rate(0.051) == 8
    assert score_overhead(9.99) == 25
    assert score_overhead(10) == 20
    assert score_overhead(50) == 20
    assert score_overhead(50.1) == 15
    assert score_overhead(100) == 15
    assert score_overhead(100.1) == 8
    assert [score_attack_coverage(n) for n in (4, 3, 2, 1, 0)] == [25, 20, 15, 8, 8]

    # T2: total equals the weighted sum of sub-scores (20 x 4 sub-scores = 80)
    assert compute_total_score(sample)["total"] == 80.0
    print("Boundary checks passed.")
