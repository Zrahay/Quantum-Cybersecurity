"""
Bell State Creation and Measurement
====================================

This module demonstrates the creation of a Bell state (|Φ+⟩) using
a Hadamard gate and a CNOT gate, then measures both qubits.

Bell states are maximally entangled two-qubit states. The |Φ+⟩ state is:

    |Phi+> = (1/sqrt(2))(|00> + |11>)

This means when we measure both qubits, we should always get the SAME
result — either both 0 or both 1 — never different values.

This is the foundation of quantum digital signatures because entangled
particles share correlated measurement outcomes regardless of distance.

No AI/ML is used. Detection will eventually rely on quantum measurement
statistics and deterministic statistical thresholds.
"""

from __future__ import annotations

from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_aer import AerSimulator


# ---------------------------------------------------------------------------
# Correlation analysis (pure statistics, no Qiskit dependency)
# ---------------------------------------------------------------------------

def analyze_correlation(counts: dict[str, int]) -> dict[str, int | float]:
    """
    Compute correlation statistics from measurement counts.

    Args:
        counts: Mapping of outcome strings (e.g. "00", "11") to their counts.
                Missing keys are treated as zero.

    Returns:
        A dictionary with:
          - total_shots      (sum of ALL counts, including unrecognised keys)
          - correlated       (|00> + |11>)
          - anti_correlated  (|01> + |10>)
          - unrecognised     (counts under any other key)
          - correlation_rate (correlated / total_shots, in 0.0-1.0)

    `correlation_rate` is a rate, not a percentage. Everything downstream
    (see contracts.DetectionResult.mismatch_rate) works in 0.0-1.0; mixing
    the two conventions is a silent factor-of-100 bug waiting to happen.

    `unrecognised` is a real signal, not defensive padding: once a noise
    model lands, or a circuit gains a register, outcome keys can appear
    that are neither correlated nor anti-correlated. Dropping them from
    the total silently would understate the shot count.
    """
    correlated = counts.get("00", 0) + counts.get("11", 0)
    anti_correlated = counts.get("01", 0) + counts.get("10", 0)
    total_shots = sum(counts.values())
    unrecognised = total_shots - correlated - anti_correlated
    correlation_rate = (correlated / total_shots) if total_shots > 0 else 0.0
    return {
        "total_shots": total_shots,
        "correlated": correlated,
        "anti_correlated": anti_correlated,
        "unrecognised": unrecognised,
        "correlation_rate": correlation_rate,
    }


def create_bell_circuit() -> QuantumCircuit:
    """
    Create a quantum circuit that prepares the Bell state |Φ+⟩.

    The circuit does the following:
      1. Applies a Hadamard (H) gate to qubit 0.
         This puts qubit 0 into superposition: |0⟩ → (|0⟩ + |1⟩)/√2
      2. Applies a CNOT gate with qubit 0 as control and qubit 1 as target.
         This entangles the two qubits.
      3. Adds measurement gates for both qubits.

    Returns:
        A QuantumCircuit with 2 qubits and 2 classical bits, ready to run.
    """
    # Create a circuit with 2 qubits and 2 classical bits
    # Qubits hold quantum information, classical bits store measurement results
    qc = QuantumCircuit(2, 2)

    # Step 1: Apply Hadamard gate to qubit 0
    # The Hadamard gate creates a superposition — qubit 0 is now
    # in a state where it could be measured as 0 or 1 with equal probability
    qc.h(0)

    # Step 2: Apply CNOT (Controlled-NOT) gate
    # Control = qubit 0, Target = qubit 1
    # If qubit 0 is |1⟩, flip qubit 1. If qubit 0 is |0⟩, leave qubit 1 alone.
    # This creates entanglement — the fates of the two qubits are now linked
    qc.cx(0, 1)

    # Step 3: Measure both qubits into classical bits
    # qubit 0 → classical bit 0, qubit 1 → classical bit 1
    #
    # BIT ORDERING: Qiskit count strings are little-endian — the RIGHTMOST
    # character is classical bit 0. So "01" means clbit1=0, clbit0=1, i.e.
    # qubit1=0, qubit0=1 — the reverse of a naive left-to-right reading.
    # Harmless here because "00"/"11" read the same from either end, but
    # teleportation applies X and Z conditioned on *specific* classical
    # bits, so getting this backwards there silently produces the wrong
    # Pauli correction. Read this comment before writing that code.
    qc.measure([0, 1], [0, 1])

    return qc


def run_bell_experiment(shots: int = 1024, seed: int | None = None) -> dict:
    """
    Run the Bell state circuit on a quantum simulator.

    Args:
        shots: Number of times to run the circuit. More shots = better
               statistics. 1024 is a standard default.
        seed:  Optional RNG seed. Pass one from tests so a failure can be
               reproduced with the exact same shots instead of guessed at.

    Returns:
        A dictionary mapping measurement outcomes to their counts.
        Example: {'00': 512, '11': 512}
    """
    # Create the Bell state circuit
    qc = create_bell_circuit()

    # Use AerSimulator — a high-performance quantum circuit simulator
    # provided by the qiskit-aer package
    simulator = AerSimulator(seed_simulator=seed)

    # Transpile the circuit for the simulator
    # Transpilation converts the circuit into instructions the simulator can run
    pm = generate_preset_pass_manager(backend=simulator, optimization_level=0)
    transpiled_qc = pm.run(qc)

    # Run the circuit
    # Each "shot" is one execution of the full circuit, from state preparation
    # to measurement. The simulator uses pseudo-random number generation to
    # produce measurement outcomes according to quantum probabilities.
    job = simulator.run(transpiled_qc, shots=shots)

    # Get the results
    result = job.result()

    # Return the counts — a dictionary like {'00': 512, '11': 512}
    counts = result.get_counts()
    return counts


def main():
    """Run the Bell state experiment and print the results."""
    print("=" * 55)
    print("  Bell State |Phi+> Experiment")
    print("  SIH26141 - Quantum-Inspired Cyber Threat Detection")
    print("=" * 55)
    print()

    # Create and display the circuit
    qc = create_bell_circuit()
    print("Circuit diagram:")
    print(qc.draw(output="text"))
    print()

    # Run the experiment with 1024 shots
    shots = 1024
    print(f"Running on AerSimulator with {shots} shots...")
    print()

    counts = run_bell_experiment(shots=shots)

    # Print the measurement counts
    print("Measurement results:")
    print("-" * 35)
    for outcome, count in sorted(counts.items()):
        percentage = (count / shots) * 100
        print(f"  |{outcome}> : {count} counts ({percentage:.1f}%)")
    print("-" * 35)
    print()

    # Correlation analysis (pure statistics — no AI/ML involved)
    analysis = analyze_correlation(counts)
    print("Correlation analysis:")
    print("-" * 35)
    print(f"  Total shots:             {analysis['total_shots']}")
    print(f"  Correlated (00 + 11):    {analysis['correlated']}")
    print(f"  Anti-correlated (01 + 10): {analysis['anti_correlated']}")
    print(f"  Unrecognised outcomes:   {analysis['unrecognised']}")
    print(f"  Correlation rate:        {analysis['correlation_rate'] * 100:.2f}%")
    print("-" * 35)
    print()

    # Explain what we see
    print("What this means:")
    print("  - We created an entangled Bell state |Phi+>")
    print("  - Both qubits are correlated: when qubit 0 is measured as 0,")
    print("    qubit 1 is ALSO 0. When qubit 0 is 1, qubit 1 is ALSO 1.")
    print("  - You should see ONLY |00> and |11> outcomes (roughly 50/50)")
    print("  - You should NOT see |01> or |10> - these would break")
    print("    the entanglement correlation")
    print()
    print("  This correlation is the foundation for quantum digital")
    print("  signatures: two parties sharing entangled particles will")
    print("  always get correlated measurement results — provided BOTH")
    print("  measure in the same basis. Measuring in different bases gives")
    print("  uncorrelated results, and that basis choice is exactly what")
    print("  the detection engine exploits to catch channel tampering.")
    print("=" * 55)

    return counts


if __name__ == "__main__":
    main()
