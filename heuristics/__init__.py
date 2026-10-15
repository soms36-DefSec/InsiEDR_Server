"""
heuristics
==========
Rule-based heuristic insider threat correlation and scoring engine.

Provides domain-specific heuristic detection for:
- Logon & Authentication anomalies (logon_rules.py)
- File exfiltration, mass creation, and tampering (file_rules.py)
- Web upload and suspicious domain access (http_rules.py)
- Removable media and unapproved device insertion (device_rules.py)

Exports:
    detect_insider_threat: Evaluates telemetry feature vectors against multi-domain heuristic rules.
"""
from __future__ import annotations

from heuristics.detector import detect_insider_threat

__all__ = ["detect_insider_threat"]
