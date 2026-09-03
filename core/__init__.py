"""Quantum core primitives for SIH26141 (Track M1).

Public surface other tracks import. Prefer these names over deep paths when
crossing the M1 boundary.
"""

from core.bell import analyze_correlation, create_bell_circuit, run_bell_experiment
from core.measurements import measure_in_basis, records_from_shots
from core.pauli import apply_correction, correction_for
from core.teleportation import teleportation_circuit

__all__ = [
    "analyze_correlation",
    "apply_correction",
    "correction_for",
    "create_bell_circuit",
    "measure_in_basis",
    "records_from_shots",
    "run_bell_experiment",
    "teleportation_circuit",
]
