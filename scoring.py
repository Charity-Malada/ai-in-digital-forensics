"""
Scoring engine for the AI Forensic Tool Evaluation Framework.

Each score_* function maps one raw metric to a 0-25 point sub-score.
The thresholds below are PLACEHOLDERS - replace them with your actual
Table 1 rubric bands before you rely on this for real results.

Keeping these as small, pure functions (no Streamlit, no I/O) means you
can unit test them directly - this is your T1/T2 test cases from the
testing plan.
"""


def score_detection_accuracy(f1_score: float) -> float:
    """F1 score (0-1) -> 0-25 pts. EDIT bands to match your Table 1."""
    if f1_score >= 0.95:
        return 25
    elif f1_score >= 0.90:
        return 20
    elif f1_score >= 0.80:
        return 15
    elif f1_score >= 0.70:
        return 10
    else:
        return 5


def score_false_positive_rate(fpr: float) -> float:
    """False positive rate as a fraction (0.02 = 2%). Lower is better."""
    if fpr <= 0.01:
        return 25
    elif fpr <= 0.03:
        return 20
    elif fpr <= 0.05:
        return 15
    elif fpr <= 0.10:
        return 10
    else:
        return 5


def score_overhead(latency_ms: float) -> float:
    """Inference latency in ms. Lower is better."""
    if latency_ms <= 10:
        return 25
    elif latency_ms <= 50:
        return 20
    elif latency_ms <= 100:
        return 15
    elif latency_ms <= 500:
        return 10
    else:
        return 5


def score_attack_coverage(categories_covered: int, total_categories: int = 15) -> float:
    """Share of attack categories the tool detects, scaled to 0-25."""
    if total_categories == 0:
        return 0
    ratio = categories_covered / total_categories
    return round(min(ratio, 1.0) * 25, 1)


DEFAULT_WEIGHTS = {"accuracy": 0.25, "fpr": 0.25, "overhead": 0.25, "coverage": 0.25}

# Presets matching the T4 sensitivity-analysis test cases
WEIGHT_PRESETS = {
    "Equal (25/25/25/25)": DEFAULT_WEIGHTS,
    "Accuracy-priority (40%)": {"accuracy": 0.40, "fpr": 0.20, "overhead": 0.20, "coverage": 0.20},
    "FPR-priority (40%)": {"accuracy": 0.20, "fpr": 0.40, "overhead": 0.20, "coverage": 0.20},
}


def compute_total_score(tool_spec: dict, weights: dict = None) -> dict:
    """
    tool_spec needs: f1_score, fpr, latency_ms, categories_covered
      (optionally total_categories, defaults to 15).
    weights: dict with accuracy/fpr/overhead/coverage fractions summing to 1.0.
    Returns sub-scores (each already 0-25) and a total scaled to 0-100.
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    sub_scores = {
        "accuracy": score_detection_accuracy(tool_spec["f1_score"]),
        "fpr": score_false_positive_rate(tool_spec["fpr"]),
        "overhead": score_overhead(tool_spec["latency_ms"]),
        "coverage": score_attack_coverage(
            tool_spec["categories_covered"], tool_spec.get("total_categories", 15)
        ),
    }
    # each sub-score is out of 25 at equal weight (0.25); rescale by weight/0.25
    total = sum(sub_scores[m] * (weights[m] / 0.25) for m in sub_scores)
    return {"sub_scores": sub_scores, "total": round(min(total, 100), 1)}


if __name__ == "__main__":
    # Quick manual sanity check - T1/T2 style. Run: python scoring.py
    sample = {"f1_score": 0.93, "fpr": 0.02, "latency_ms": 40, "categories_covered": 11}
    print("Equal weights:", compute_total_score(sample))
    print("Accuracy-priority:", compute_total_score(sample, WEIGHT_PRESETS["Accuracy-priority (40%)"]))
    assert score_detection_accuracy(0.95) == 25
    assert score_detection_accuracy(0.949) == 20
    assert score_false_positive_rate(0.01) == 25
    print("Boundary checks passed.")
