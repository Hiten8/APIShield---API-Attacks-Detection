"""Ranking metrics used for early stopping and threshold selection."""

from __future__ import annotations

import math


def sigmoid(logit: float) -> float:
    if logit >= 0:
        z = math.exp(-logit)
        return 1.0 / (1.0 + z)
    z = math.exp(logit)
    return z / (1.0 + z)


def roc_auc(y_true: list[int], scores: list[float]) -> float:
    positives = [s for y, s in zip(y_true, scores) if y == 1]
    negatives = [s for y, s in zip(y_true, scores) if y == 0]
    if not positives or not negatives:
        return float("nan")
    correct = 0.0
    ties = 0.0
    for p in positives:
        for n in negatives:
            if p > n:
                correct += 1
            elif p == n:
                ties += 1
    return (correct + 0.5 * ties) / (len(positives) * len(negatives))


def average_precision(y_true: list[int], scores: list[float]) -> float:
    paired = sorted(zip(scores, y_true), key=lambda row: row[0], reverse=True)
    tp = 0
    fp = 0
    total_pos = sum(y_true)
    if total_pos == 0:
        return float("nan")
    precision_sum = 0.0
    for _score, label in paired:
        if label == 1:
            tp += 1
            precision_sum += tp / (tp + fp)
        else:
            fp += 1
    return precision_sum / total_pos


def binary_f1(y_true: list[int], y_hat: list[int]) -> float:
    tp = sum(1 for y, p in zip(y_true, y_hat) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(y_true, y_hat) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(y_true, y_hat) if y == 1 and p == 0)
    if tp == 0:
        return 0.0
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def false_positive_rate(y_true: list[int], y_hat: list[int]) -> float:
    negatives = sum(1 for y in y_true if y == 0)
    if negatives == 0:
        return float("nan")
    fp = sum(1 for y, p in zip(y_true, y_hat) if y == 0 and p == 1)
    return fp / negatives


def choose_threshold(
    y_true: list[int],
    scores: list[float],
    *,
    target_fpr: float = 0.05,
) -> dict[str, float]:
    """
    Prefer the highest-F1 threshold whose FPR is <= target_fpr.
    If none qualify, fall back to global max F1.
    """

    candidates = sorted(set(scores))
    if not candidates:
        return {"tau": 0.5, "f1": 0.0, "fpr": 1.0, "method": "default"}

    best_constrained: tuple[float, float, float] | None = None
    best_any: tuple[float, float, float] | None = None

    for tau in candidates:
        y_hat = [1 if score >= tau else 0 for score in scores]
        f1 = binary_f1(y_true, y_hat)
        fpr = false_positive_rate(y_true, y_hat)
        if math.isnan(fpr):
            fpr = 1.0
        if best_any is None or f1 > best_any[0]:
            best_any = (f1, tau, fpr)
        if fpr <= target_fpr and (best_constrained is None or f1 > best_constrained[0]):
            best_constrained = (f1, tau, fpr)

    if best_constrained is not None:
        f1, tau, fpr = best_constrained
        return {"tau": tau, "f1": f1, "fpr": fpr, "method": "max_f1_fpr_cap"}
    f1, tau, fpr = best_any or (0.0, 0.5, 1.0)
    return {"tau": tau, "f1": f1, "fpr": fpr, "method": "max_f1"}
