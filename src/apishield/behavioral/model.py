"""Binary GINE classifier over windowed endpoint-transition graphs."""

from __future__ import annotations

import torch
from torch import nn
from torch_geometric.nn import GINEConv, global_max_pool, global_mean_pool


class WindowGNN(nn.Module):
    """
    2-layer GINE + global mean/max pool + graph extras → 1 logit.

    Node ids (OpenAPI template vocab) are embedded and added to numeric
    visit/Δt/error features. Edge attributes carry transition count and Δt.
    """

    def __init__(
        self,
        *,
        vocab_size: int,
        node_numeric_dim: int = 4,
        edge_dim: int = 3,
        graph_attr_dim: int = 5,
        hidden_dim: int = 64,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.node_embed = nn.Embedding(vocab_size, hidden_dim)
        self.node_numeric = nn.Linear(node_numeric_dim, hidden_dim)
        self.edge_encoder = nn.Sequential(
            nn.Linear(edge_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )
        self.conv1 = GINEConv(
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            ),
            edge_dim=hidden_dim,
        )
        self.conv2 = GINEConv(
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            ),
            edge_dim=hidden_dim,
        )
        self.dropout = nn.Dropout(dropout)
        self.head = nn.Sequential(
            nn.Linear(hidden_dim * 2 + graph_attr_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, data) -> torch.Tensor:
        edge_attr = self.edge_encoder(data.edge_attr)
        x = self.node_embed(data.n_id) + self.node_numeric(data.x)
        x = self.conv1(x, data.edge_index, edge_attr).relu()
        x = self.dropout(x)
        x = self.conv2(x, data.edge_index, edge_attr).relu()
        pooled = torch.cat(
            [
                global_mean_pool(x, data.batch),
                global_max_pool(x, data.batch),
            ],
            dim=1,
        )
        graph_attr = data.graph_attr
        if graph_attr.dim() == 3:
            graph_attr = graph_attr.reshape(graph_attr.size(0), -1)
        elif graph_attr.dim() == 1:
            graph_attr = graph_attr.unsqueeze(0)
        if graph_attr.size(0) != pooled.size(0) and graph_attr.size(0) == 1:
            graph_attr = graph_attr.expand(pooled.size(0), -1)
        logits = self.head(torch.cat([pooled, graph_attr], dim=1)).squeeze(-1)
        return logits
