"""
Train the rolling-window GNN on processed window graphs (CPU-friendly).

Example:
  python scripts/train_behavioral_gnn.py
  python scripts/train_behavioral_gnn.py --windows data/processed/windows.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import torch
from torch.nn import BCEWithLogitsLoss
from torch.optim import Adam
from torch_geometric.loader import DataLoader

from apishield.behavioral.dataset import (
    assign_splits,
    load_window_records,
    partition_records,
    pyg_dataset,
)
from apishield.behavioral.graphs import EndpointResolver
from apishield.behavioral.metrics import (
    average_precision,
    binary_f1,
    choose_threshold,
    false_positive_rate,
    roc_auc,
    sigmoid,
)
from apishield.behavioral.model import WindowGNN
from apishield.conformance.openapi_loader import OpenAPILoader


DEFAULT_WINDOWS = ROOT / "data" / "processed" / "windows.jsonl"
DEFAULT_SPEC = ROOT / "targets" / "crAPI-main" / "openapi-spec" / "crapi-openapi-spec.json"
DEFAULT_CKPT = ROOT / "data" / "processed" / "behavioral_gnn.pt"
DEFAULT_THRESHOLD = ROOT / "data" / "processed" / "threshold.json"


def set_seed(seed: int) -> None:
    torch.manual_seed(seed)


def _graph_field(batch, name: str, index: int) -> Any:
    value = getattr(batch, name)
    if isinstance(value, (list, tuple)):
        return value[index]
    return value


def attack_type_weights(records: list[dict[str, Any]]) -> list[float]:
    counts = Counter(str(record["attack_type"]) for record in records)
    return [1.0 / counts[str(record["attack_type"])] for record in records]


def evaluate(model: WindowGNN, loader: DataLoader, device: torch.device) -> dict[str, Any]:
    model.eval()
    logits: list[float] = []
    labels: list[int] = []
    session_best: dict[str, float] = {}
    session_y: dict[str, int] = {}
    session_type: dict[str, str] = {}
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            batch_logits = model(batch).detach().cpu()
            batch_y = batch.y.detach().cpu().view(-1)
            for index, logit in enumerate(batch_logits.tolist()):
                score = sigmoid(logit)
                label = int(batch_y[index].item())
                logits.append(logit)
                labels.append(label)
                session_id = str(_graph_field(batch, "session_id", index))
                session_best[session_id] = max(session_best.get(session_id, float("-inf")), score)
                session_y[session_id] = label
                session_type[session_id] = str(_graph_field(batch, "attack_type", index))
    scores = [sigmoid(v) for v in logits]
    session_ids = list(session_best)
    session_scores = [session_best[s] for s in session_ids]
    session_labels = [session_y[s] for s in session_ids]
    return {
        "window_labels": labels,
        "window_scores": scores,
        "session_labels": session_labels,
        "session_scores": session_scores,
        "session_types": [session_type[s] for s in session_ids],
        "pr_auc": average_precision(labels, scores),
        "roc_auc": roc_auc(labels, scores),
        "session_pr_auc": average_precision(session_labels, session_scores),
        "session_roc_auc": roc_auc(session_labels, session_scores),
    }


def recall_by_type(
    session_types: list[str],
    session_labels: list[int],
    session_scores: list[float],
    tau: float,
) -> dict[str, float]:
    grouped: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for attack_type, y, score in zip(session_types, session_labels, session_scores):
        grouped[attack_type].append((y, 1 if score >= tau else 0))
    out: dict[str, float] = {}
    for attack_type, pairs in grouped.items():
        positives = [(y, p) for y, p in pairs if y == 1]
        if not positives:
            continue
        out[attack_type] = sum(p for _y, p in positives) / len(positives)
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train window GNN (CPU).")
    parser.add_argument("--windows", type=Path, default=DEFAULT_WINDOWS)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CKPT)
    parser.add_argument("--threshold-out", type=Path, default=DEFAULT_THRESHOLD)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--dropout", type=float, default=0.2)
    parser.add_argument("--patience", type=int, default=8)
    parser.add_argument("--target-fpr", type=float, default=0.05)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.windows.exists():
        raise FileNotFoundError(
            f"Window JSONL not found: {args.windows}. "
            "Run scripts/build_behavioral_windows.py first."
        )

    set_seed(args.seed)
    device = torch.device("cpu")
    spec = OpenAPILoader().load(args.spec)
    resolver = EndpointResolver(spec)

    records = load_window_records(args.windows)
    if not records:
        raise ValueError(f"No windows in {args.windows}")

    assignment = assign_splits(records, seed=args.seed)
    parts = partition_records(records, assignment)
    print(
        "windows",
        {split: len(rows) for split, rows in parts.items()},
        "sessions",
        len(assignment),
    )

    train_data = pyg_dataset(parts["train"])
    val_data = pyg_dataset(parts["val"])
    test_data = pyg_dataset(parts["test"])

    train_weights = torch.tensor(attack_type_weights(parts["train"]), dtype=torch.double)
    sampler = torch.utils.data.WeightedRandomSampler(
        weights=train_weights,
        num_samples=len(train_data),
        replacement=True,
    )
    train_loader = DataLoader(train_data, batch_size=args.batch_size, sampler=sampler)
    val_loader = DataLoader(val_data, batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)

    n_pos = sum(int(r["y"]) for r in parts["train"])
    n_neg = len(parts["train"]) - n_pos
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)], dtype=torch.float)

    model = WindowGNN(
        vocab_size=resolver.vocab_size,
        hidden_dim=args.hidden_dim,
        dropout=args.dropout,
    ).to(device)
    criterion = BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    best_state = None
    best_pr = float("-inf")
    stale = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        n_batches = 0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            logits = model(batch)
            loss = criterion(logits, batch.y.view(-1))
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item())
            n_batches += 1
        val_metrics = evaluate(model, val_loader, device)
        pr_auc = val_metrics["pr_auc"]
        mean_loss = total_loss / max(n_batches, 1)
        print(
            f"epoch {epoch:02d} loss={mean_loss:.4f} "
            f"val_pr_auc={pr_auc:.4f} val_roc_auc={val_metrics['roc_auc']:.4f}"
        )
        if pr_auc > best_pr:
            best_pr = pr_auc
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= args.patience:
                print(f"early stop at epoch {epoch}")
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    val_metrics = evaluate(model, val_loader, device)
    chosen = choose_threshold(
        val_metrics["session_labels"] or val_metrics["window_labels"],
        val_metrics["session_scores"] or val_metrics["window_scores"],
        target_fpr=args.target_fpr,
    )
    tau = float(chosen["tau"])
    test_metrics = evaluate(model, test_loader, device)
    y_hat = [1 if s >= tau else 0 for s in test_metrics["session_scores"]]
    type_recall = recall_by_type(
        test_metrics["session_types"],
        test_metrics["session_labels"],
        test_metrics["session_scores"],
        tau,
    )
    print("threshold", chosen)
    print(
        "test session pr_auc",
        test_metrics["session_pr_auc"],
        "roc_auc",
        test_metrics["session_roc_auc"],
        "f1",
        binary_f1(test_metrics["session_labels"], y_hat),
        "fpr",
        false_positive_rate(test_metrics["session_labels"], y_hat),
    )
    print("test recall by attack_type", type_recall)

    args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state": model.state_dict(),
            "vocab": resolver.vocab,
            "hidden_dim": args.hidden_dim,
            "dropout": args.dropout,
            "window_size": 16,
            "infer_stride": 4,
            "min_infer_events": 4,
        },
        args.checkpoint,
    )
    threshold_payload = {
        "tau": tau,
        "method": chosen["method"],
        "val_f1": chosen["f1"],
        "val_fpr": chosen["fpr"],
        "val_window_pr_auc": val_metrics["pr_auc"],
        "test_session_pr_auc": test_metrics["session_pr_auc"],
        "test_session_roc_auc": test_metrics["session_roc_auc"],
        "test_recall_by_type": type_recall,
        "seed": args.seed,
    }
    args.threshold_out.write_text(
        json.dumps(threshold_payload, indent=2),
        encoding="utf-8",
    )
    print(f"saved {args.checkpoint}")
    print(f"saved {args.threshold_out}")


if __name__ == "__main__":
    main()
