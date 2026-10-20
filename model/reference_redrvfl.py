"""
Tier 3: InsiEDR Deep RedRVFL (Recurrent/Residual Ensemble Random Vector Functional Link)
Neural Temporal Sequence Drift Detection Module.

Architecture:
- Frozen RandomLSTM Layers with orthogonal projections
- Direct skip-connections from input sequence to output layer (RVFL property)
- Closed-form Ridge Regression solvers for ultra-fast, robust forecasting
- Sequence Prediction Error (|y - y_hat|) measures temporal behavioral drift
"""

import numpy as np
import torch
import torch.nn as nn
from sklearn.linear_model import Ridge
import joblib

class RandomLSTM(nn.Module):
    """
    Frozen Random LSTM layer with non-trainable orthogonal parameters.
    Extracts deep non-linear temporal dynamics without gradient descent.
    """
    def __init__(self, input_size, hidden_size, seed=42):
        super().__init__()
        torch.manual_seed(seed)
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            batch_first=True
        )
        # Freeze all weights
        for p in self.lstm.parameters():
            p.requires_grad = False
        self.eval()

    def forward(self, x):
        batch_size = x.shape[0]
        chunk_size = 8192
        if batch_size <= chunk_size:
            with torch.no_grad():
                _, (h_n, _) = self.lstm(x)
            return h_n[-1]

        h_ns = []
        with torch.no_grad():
            for i in range(0, batch_size, chunk_size):
                end_i = min(i + chunk_size, batch_size)
                _, (h_n_chunk, _) = self.lstm(x[i:end_i])
                h_ns.append(h_n_chunk[-1])
        return torch.cat(h_ns, dim=0)


def build_layer_input(previous_hidden, xtensor):
    """
    Deep RedRVFL recurrence: Layer l receives [h_(l-1), X] across the time window.
    """
    window_size = xtensor.shape[1]
    hidden_expanded = previous_hidden.unsqueeze(1).repeat(1, window_size, 1)
    return torch.cat([xtensor, hidden_expanded], dim=2)


def build_feature_matrix(xtensor, hidden_tensor):
    """
    Constructs the RVFL skip-connection feature matrix D:
    D = [Flattened(X_window), Hidden_State]
    """
    batch_size = xtensor.shape[0]
    x_flat = xtensor.reshape(batch_size, -1).detach().cpu().numpy()
    h_np = hidden_tensor.detach().cpu().numpy()
    return np.hstack([x_flat, h_np])


class RedRVFLOrchestrator:
    """
    Deep RedRVFL Orchestrator:
    Manages multi-layer RandomLSTM feature extractors, skip-connection matrix construction,
    and Ridge regression ensemble.
    """
    def __init__(self, input_features, hidden_size=64, num_layers=3, ridge_alpha=0.01, seed=42):
        self.input_features = input_features
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.ridge_alpha = ridge_alpha
        self.seed = seed
        self.layers = []
        self.ridge_models = []
        self.fitted = False

        for i in range(num_layers):
            layer_seed = seed + i * 100
            in_size = input_features if i == 0 else (input_features + hidden_size)
            self.layers.append(RandomLSTM(in_size, hidden_size, seed=layer_seed))

    def extract_features(self, X_tensor):
        """
        Extracts feature matrices D across all RandomLSTM layers.
        """
        feature_matrices = []
        xtensor_current = X_tensor

        for i in range(self.num_layers):
            lstm = self.layers[i]
            hidden = lstm(xtensor_current)
            D = build_feature_matrix(X_tensor, hidden)
            feature_matrices.append(D)
            if i < self.num_layers - 1:
                xtensor_current = build_layer_input(hidden, X_tensor)

        return feature_matrices

    def fit(self, X_seq, y_seq):
        """
        Trains closed-form Ridge regression models across all RedRVFL layers on clean training sequences.
        """
        X_tensor = torch.tensor(X_seq, dtype=torch.float32)
        y_arr = np.asarray(y_seq, dtype=float)

        feature_matrices = self.extract_features(X_tensor)
        self.ridge_models = []

        for D in feature_matrices:
            ridge = Ridge(alpha=self.ridge_alpha, solver="lsqr")
            ridge.fit(D, y_arr)
            self.ridge_models.append(ridge)

        self.fitted = True
        return self

    def predict(self, X_seq):
        """
        Generates ensemble trajectory forecast by taking median prediction across layers.
        """
        if not self.fitted:
            raise ValueError("RedRVFL must be fitted before predict.")

        X_tensor = torch.tensor(X_seq, dtype=torch.float32)
        feature_matrices = self.extract_features(X_tensor)

        preds = []
        for i, ridge in enumerate(self.ridge_models):
            D = feature_matrices[i]
            preds.append(ridge.predict(D))

        preds = np.array(preds)
        return np.median(preds, axis=0)

    def compute_sequence_error(self, X_seq, y_seq):
        """
        Computes sequential forecasting reconstruction error: |y - y_hat|.
        High error represents abnormal behavioral sequence drift.
        """
        preds = self.predict(X_seq)
        y_arr = np.asarray(y_seq, dtype=float)
        errors = np.abs(y_arr - preds)
        return np.clip(errors, 0.0, 1.0)
