from __future__ import annotations

from unittest.mock import MagicMock

from server.api.export import _extract_parameters, _prepare_training_export_page


def test_training_export_bulk_loads_features_once_for_missing_payloads():
    storage = MagicMock()
    storage.get_feature_vectors.return_value = {
        "payload-a": {"count": 0.0},
        "payload-b": {"active": 0.0},
    }
    rows = [
        {"payload_id": "payload-a", "payload": None},
        {"payload_id": "payload-b", "payload": None},
    ]

    _prepare_training_export_page(storage, rows)

    storage.get_feature_vectors.assert_called_once_with(["payload-a", "payload-b"])
    assert _extract_parameters(storage, rows[0]) == {"count": 0.0}
    assert _extract_parameters(storage, rows[1]) == {"active": 0.0}
    storage.get_feature_vector.assert_not_called()
