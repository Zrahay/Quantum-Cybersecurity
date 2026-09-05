"""Streamlit dashboard. Track M5 (Nikita). Deliverable D5.

Renders DetectionResult and recomputes nothing. If the dashboard and the
engine ever disagree you will find out live in front of a judge.
"""

from __future__ import annotations

import math
import time

import numpy as np
import pandas as pd
import streamlit as st

from contracts import (
    Basis,
    DetectionResult,
    Signature,
    ThreatType,
    Verdict,
)
from attacks.replay import ReplayAdversary
from attacks.forgery import ForgeryAdversary
from attacks.channel_tamper import ChannelTamperAdversary
from attacks.impersonation import ImpersonationAdversary
from attacks.pns import PNSAdversary
from attacks.collective import CollectiveAttackAdversary
from attacks.faked_state import FakedStateAdversary
from attacks.time_shift import TimeShiftAdversary
from attacks.trojan_horse import TrojanHorseAdversary
from attacks.mitm_classical import MitmClassicalAdversary
from detection.detector import evaluate
from detection.statistics import mismatch_rate
from protocol import keygen, sign, verify, QDSConfig, M1QuantumCore


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SIH26141 — QDS Threat Detection",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS for polished look
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Global spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        padding-left: 3rem;
        padding-right: 3rem;
    }

    /* Card styling */
    .metric-card {
        background: white;
        border: 1px solid #e9ecef;
        border-radius: 12px;
        padding: 1.25rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        transition: box-shadow 0.2s, transform 0.2s;
    }
    .metric-card:hover {
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        transform: translateY(-1px);
    }

    .verdict-card {
        border-radius: 16px;
        padding: 1.5rem;
        border: 2px solid;
        box-shadow: 0 4px 16px rgba(0,0,0,0.08);
    }

    /* Button styling */
    .stButton > button {
        border-radius: 10px;
        font-weight: 600;
        transition: all 0.15s ease;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .stButton > button:active {
        transform: translateY(0);
    }

    /* Attack buttons - distinct colors */
    .attack-replay button { background: #6f42c1 !important; border-color: #6f42c1 !important; color: white !important; }
    .attack-forgery button { background: #dc3545 !important; border-color: #dc3545 !important; color: white !important; }
    .attack-channel_tamper button { background: #20c997 !important; border-color: #20c997 !important; color: white !important; }
    .attack-impersonation button { background: #fd7e14 !important; border-color: #fd7e14 !important; color: white !important; }
    .attack-pns button { background: #0d6efd !important; border-color: #0d6efd !important; color: white !important; }
    .attack-collective button { background: #6f42c1 !important; border-color: #6f42c1 !important; color: white !important; }
    .attack-faked_state button { background: #6c757d !important; border-color: #6c757d !important; color: white !important; }
    .attack-time_shift button { background: #ffc107 !important; border-color: #ffc107 !important; color: black !important; }
    .attack-trojan_horse button { background: #8B4513 !important; border-color: #8B4513 !important; color: white !important; }
    .attack-mitm_classical button { background: #fd7e14 !important; border-color: #fd7e14 !important; color: white !important; }

    /* Primary action */
    .sign-button button { background: #28a745 !important; border-color: #28a745 !important; font-size: 1.1rem !important; padding: 0.75rem 1.5rem !important; }

    /* Dataframe styling */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid #e9ecef;
    }

    /* Expander styling */
    .streamlit-expanderHeader {
        font-weight: 600;
        font-size: 1rem;
    }

    /* Input styling */
    .stTextInput > div > div > input {
        border-radius: 10px;
        border: 2px solid #e9ecef;
        font-family: 'Monospace', monospace;
        font-size: 1.1rem;
        letter-spacing: 0.1em;
    }
    .stTextInput > div > div > input:focus {
        border-color: #28a745;
        box-shadow: 0 0 0 3px rgba(40,167,69,0.15);
    }

    /* Metric styling */
    [data-testid="metric-container"] {
        background: white;
        border: 1px solid #e9ecef;
        border-radius: 12px;
        padding: 1rem 1.25rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    [data-testid="metric-container"] > div {
        gap: 0.5rem;
    }

    /* Divider */
    hr {
        border-color: #e9ecef;
        margin: 1.5rem 0;
    }

    /* Status badges */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.35rem 0.85rem;
        border-radius: 999px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .status-active { background: #d4edda; color: #155724; }
    .status-waiting { background: #fff3cd; color: #856404; }

    /* Section headers */
    h2 { font-weight: 700; color: #212529; margin-bottom: 1rem; }
    h3 { font-weight: 600; color: #343a40; margin-bottom: 0.75rem; }

    /* Keep Streamlit's header control visible: it is the only way to reopen
       the sidebar after a browser session restores it in its collapsed state. */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header[data-testid="stHeader"] { background: transparent; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state initialization
# ---------------------------------------------------------------------------
def _init_state() -> None:
    defaults = {
        "signer_key": None,
        "signer_id": "alice",
        "event_log": [],
        "seen_nonces": set(),
        "last_signature": None,
        "last_detection": None,
        "quantum_core": M1QuantumCore(),
        "config": QDSConfig(bases=(Basis.Z, Basis.X)),
        # The number of message bits the active key was generated for.
        # Independent of n_copies (L) -- P1's message_length and its
        # security parameter L are two different dials. Tracked here
        # rather than read off KeyPair, which doesn't expose it publicly.
        "message_length": 4,
        "message_input": "1010",
        "last_action": None,
        "action_timestamp": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _verdict_color(verdict: Verdict) -> str:
    return {
        Verdict.ACCEPT: "#28a745",
        Verdict.ACCEPT_NO_TRANSFER: "#ffc107",
        Verdict.REJECT: "#dc3545",
    }.get(verdict, "#6c757d")


def _verdict_label(verdict: Verdict) -> str:
    return {
        Verdict.ACCEPT: "✅ ACCEPT",
        Verdict.ACCEPT_NO_TRANSFER: "⚠️ ACCEPT (No Transfer)",
        Verdict.REJECT: "❌ REJECT",
    }.get(verdict, "❓ UNKNOWN")


def _threat_color(threat: ThreatType) -> str:
    return {
        ThreatType.NONE: "#28a745",
        ThreatType.FORGERY: "#dc3545",
        ThreatType.IMPERSONATION: "#fd7e14",
        ThreatType.REPLAY: "#6f42c1",
        ThreatType.CHANNEL_TAMPER: "#20c997",
    }.get(threat, "#6c757d")


def _threat_label(threat: ThreatType) -> str:
    return {
        ThreatType.NONE: "✅ None",
        ThreatType.FORGERY: "🔴 Forgery",
        ThreatType.IMPERSONATION: "🟠 Impersonation",
        ThreatType.REPLAY: "🟣 Replay",
        ThreatType.CHANNEL_TAMPER: "🟢 Channel Tamper",
    }.get(threat, "❓ Unknown")


def _calibrated_noise_floor(config: QDSConfig) -> float:
    """The mismatch rate a KNOWN-legitimate signature gets at the current
    channel config -- i.e. the independent `noise_floor` evaluate() needs.

    `config.noise_level` is a depolarising-channel DIAL, not a mismatch
    rate -- detection/detector.py's module docstring and QDSConfig's own
    docstring both say this must be MEASURED, not assumed (they are only
    roughly related: e.g. noise_level 0.3 has empirically measured around
    a 0.14 mismatch rate, not 0.3). This runs one throwaway
    keygen/sign/verify at the current config and measures it directly,
    rather than passing noise_level straight through.

    Cached per (n_copies, noise_level, bases) in session state, since it
    is expensive (a real quantum-core run) and only changes when the
    channel config does -- not on every signature.
    """
    cache = st.session_state.setdefault("_noise_floor_cache", {})
    cache_key = (config.n_copies, config.noise_level, config.bases)
    if cache_key in cache:
        return cache[cache_key]
    core = M1QuantumCore()
    cal_key = keygen("_calibration", config.n_copies, message_length=1, core=core, config=config)
    cal_sig = sign((0,), cal_key, core=core, config=config)
    cal_records = verify(cal_sig, cal_key, core=core, config=config)
    floor = mismatch_rate(cal_records) if cal_records else 0.0
    cache[cache_key] = floor
    return floor


def _run_full_pipeline(sig: Signature) -> DetectionResult:
    records = verify(sig, st.session_state.signer_key, core=st.session_state.quantum_core, config=st.session_state.config)
    noise_floor = _calibrated_noise_floor(st.session_state.config)
    result = evaluate(records, sig, st.session_state.seen_nonces, noise_floor=noise_floor)
    st.session_state.seen_nonces.add(sig.nonce)
    return result


def _log_event(sig: Signature, result: DetectionResult, attack_label: str | None = None) -> None:
    st.session_state.event_log.insert(0, {  # newest first
        "time": time.strftime("%H:%M:%S", time.localtime(result.timestamp)),
        "sig_id": sig.sig_id[:12] + "…",
        "signer": sig.signer_id,
        "message": "".join(str(b) for b in sig.message),
        "attack": attack_label or "Legitimate",
        "verdict": result.verdict.value,
        "threat": result.threat.value,
        "mismatch": f"{result.mismatch_rate:.2%}",
        "forgery_bound": f"{result.forgery_prob_bound:.2e}",
        "reason": result.reason,
    })


def _render_verdict_card(result: DetectionResult) -> None:
    verdict_color = _verdict_color(result.verdict)
    threat_color = _threat_color(result.threat)

    st.markdown(
        f"""
        <div class="verdict-card" style="border-color: {verdict_color}; background: {verdict_color}15;">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <div style="font-size: 1.5rem; font-weight: 700; color: {verdict_color};">{_verdict_label(result.verdict)}</div>
                    <div style="font-size: 1.1rem; font-weight: 500; color: {threat_color}; margin-top: 0.25rem;">{_threat_label(result.threat)}</div>
                </div>
                <div style="text-align: right; min-width: 180px;">
                    <div style="font-size: 0.85rem; color: #6c757d;">Mismatch Rate</div>
                    <div style="font-size: 2rem; font-weight: 700; color: {verdict_color};">{result.mismatch_rate:.2%}</div>
                </div>
            </div>
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid {verdict_color}30; color: #495057;">
                <strong>Reason:</strong> {result.reason}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_metrics_row(result: DetectionResult) -> None:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Measurements", result.n_measurements, help="Total projective measurements performed")
    with c2:
        st.metric("Forgery Bound", f"{result.forgery_prob_bound:.2e}", help="Hoeffding bound on forgery probability")
    with c3:
        st.metric("χ² Statistic", f"{result.chi2_stat:.3f}", help="Chi-square goodness-of-fit statistic")
    with c4:
        p_val = result.chi2_p_value
        delta_color = "normal" if p_val > 0.05 else "inverse"
        st.metric("χ² p-value", f"{p_val:.4f}", help="p-value of uniformity test", delta_color=delta_color)


# ---------------------------------------------------------------------------
# Sidebar: Key Generation & Config
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔐 Key Generation")

    if st.session_state.signer_key is None:
        st.markdown('<span class="status-badge status-waiting">⏳ No key generated</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-badge status-active">✅ Key active</span>', unsafe_allow_html=True)

    signer_id = st.text_input(
        "Signer ID",
        value=st.session_state.signer_id,
        key="sidebar_signer_id",
        placeholder="alice",
    )

    n_copies = st.number_input(
        "Copies (L)",
        min_value=1,
        max_value=128,
        value=st.session_state.config.n_copies,
        step=1,
        help="Number of signature copies per verifier, per message bit. Higher L = stronger security.",
    )

    message_length = st.number_input(
        "Message length (bits)",
        min_value=1,
        max_value=32,
        value=st.session_state.message_length,
        step=1,
        help=(
            "How many message bits this key can sign. Independent of L: "
            "P1 needs 2 * message_length * L key elements, one L-sized "
            "sequence pair per message bit position."
        ),
    )

    if st.button("🔑 Generate Keys", type="primary", use_container_width=True):
        with st.spinner("Generating quantum keys..."):
            st.session_state.signer_id = signer_id
            st.session_state.config = QDSConfig(
                n_copies=n_copies,
                bases=(Basis.Z, Basis.X),
            )
            st.session_state.message_length = message_length
            # Keep the dashboard input valid for the active key's
            # message_length rather than letting sign() raise a
            # ValueError the user has to decode from a traceback.
            st.session_state.message_input = "10" * (message_length // 2) + ("1" if message_length % 2 else "")
            st.session_state.quantum_core = M1QuantumCore()
            st.session_state.signer_key = keygen(
                signer_id, n_copies,
                message_length=message_length,
                core=st.session_state.quantum_core,
                config=st.session_state.config,
            )
            st.session_state.seen_nonces.clear()
            st.session_state.event_log.clear()
            st.session_state.last_signature = None
            st.session_state.last_detection = None
            st.session_state.last_action = "keygen"
            st.session_state.action_timestamp = time.time()
        st.success(f"Generated key for **{signer_id}** with L = **{n_copies}**, message length = **{message_length}** bits")
        st.rerun()

    st.markdown("---")

    st.markdown("### ⚙️ Measurement Bases")

    basis_options = {
        "Z only": (Basis.Z,),
        "Z, X": (Basis.Z, Basis.X),
        "Z, X, Y": (Basis.Z, Basis.X, Basis.Y),
    }
    current_bases = st.session_state.config.bases if st.session_state.config.bases else (Basis.Z, Basis.X)
    basis_labels = {v: k for k, v in basis_options.items()}
    selected_basis_label = st.selectbox(
        "Measurement Bases",
        options=list(basis_options.keys()),
        index=list(basis_options.values()).index(current_bases) if current_bases in basis_options.values() else 1,
        help="Bases used for verification measurements. More bases = more detection power.",
    )
    selected_bases = basis_options[selected_basis_label]
    if selected_bases != st.session_state.config.bases:
        st.session_state.config = QDSConfig(
            n_copies=st.session_state.config.n_copies,
            noise_level=st.session_state.config.noise_level,
            bases=selected_bases,
        )
        st.rerun()

    st.markdown("---")

    st.markdown("### ⚙️ Channel Configuration")

    noise_level = st.slider(
        "Depolarising Noise",
        0.0, 1.0,
        st.session_state.config.noise_level,
        0.05,
        help="Simulates channel tampering. M3 turns this dial up.",
    )
    if noise_level != st.session_state.config.noise_level:
        st.session_state.config = QDSConfig(n_copies=st.session_state.config.n_copies, noise_level=noise_level)
        st.rerun()

    # Visual noise indicator
    noise_pct = int(noise_level * 100)
    noise_color = "#28a745" if noise_pct == 0 else ("#ffc107" if noise_pct < 30 else "#dc3545")
    st.markdown(
        f"""
        <div style="margin-top: 0.5rem;">
            <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
                <span>Channel Quality</span>
                <span style="color: {noise_color}; font-weight: 600;">{100 - noise_pct}% clean</span>
            </div>
            <div style="height: 6px; background: #e9ecef; border-radius: 3px; overflow: hidden;">
                <div style="width: {100 - noise_pct}%; height: 100%; background: {noise_color}; border-radius: 3px; transition: width 0.3s;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    st.markdown("### 🧪 Debug")
    if st.button("🗑️ Clear Event Log", use_container_width=True):
        st.session_state.event_log.clear()
        st.rerun()

    st.caption(f"📋 Known nonces: **{len(st.session_state.seen_nonces)}**")


# ---------------------------------------------------------------------------
# Main UI
# ---------------------------------------------------------------------------
def main() -> None:
    # Header
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0 2rem 0;">
        <h1 style="margin: 0; font-size: 2.5rem; font-weight: 800; background: linear-gradient(90deg, #28a745, #20c997); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🔐 SIH26141 — QDS Threat Detection</h1>
        <p style="margin: 0.5rem 0 0 0; color: #6c757d; font-size: 1.1rem;">Track M5 Dashboard · No ML · Pure Quantum Statistics</p>
    </div>
    """, unsafe_allow_html=True)

    # Key status banner
    if st.session_state.signer_key is None:
        st.warning("⚠️ **Generate a signer key in the sidebar** to begin signing and testing attacks.")
        return

    key = st.session_state.signer_key

    # Active key info card
    st.markdown(
        f"""
        <div class="metric-card" style="margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <span style="font-size: 0.75rem; color: #6c757d; text-transform: uppercase; letter-spacing: 0.05em;">Active Key</span>
                    <div style="font-family: monospace; font-size: 1rem; font-weight: 600; color: #212529; margin-top: 0.25rem;">{key.key_id}</div>
                </div>
                <div style="display: flex; gap: 2rem; align-items: center;">
                    <div>
                        <div style="font-size: 0.75rem; color: #6c757d;">Signer</div>
                        <div style="font-weight: 600;">{key.signer_id}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: #6c757d;">Copies (L)</div>
                        <div style="font-weight: 600;">{key.n_copies}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: #6c757d;">Noise</div>
                        <div style="font-weight: 600;">{st.session_state.config.noise_level:.0%}</div>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- Signing Section ---
    st.markdown("### ✍️ Sign Message")

    col_msg, col_sign = st.columns([4, 1], gap="large")

    with col_msg:
        message_str = st.text_input(
            "Message (bits)",
            max_chars=64,
            placeholder="Enter binary string (e.g., 10101010)",
            label_visibility="collapsed",
            key="message_input",
        )

    with col_sign:
        st.write("")  # spacer for alignment
        sign_clicked = st.button("✍️ Sign", type="primary", use_container_width=True)

    # Parse message
    try:
        message_bits = tuple(int(b) for b in message_str if b in "01")
        if len(message_bits) != len(message_str) or len(message_bits) == 0:
            raise ValueError
    except ValueError:
        st.error("❌ Message must contain only 0 and 1 (at least one bit)")
        return

    required_length = st.session_state.message_length
    if len(message_bits) != required_length:
        st.error(
            f"❌ The active key was generated for **{required_length}-bit** messages. "
            "Generate a new key with a different message length in the sidebar to sign "
            "a message of this length."
        )
        return

    # --- Attack Section ---
    st.markdown("### 🎯 Launch Attack")
    st.caption("Attacks are applied to the **last signed message**. Sign a message first.")

    attack_adversaries = {
        "Replay": (ReplayAdversary(seen_nonces=set()), "🔁 Replay", "attack-replay", "Reuses the exact same signature + nonce"),
        "Forgery": (ForgeryAdversary(strength=1.0), "🔴 Forgery", "attack-forgery", "Random Pauli ops, real teleportation outcomes"),
        "Channel Tamper": (ChannelTamperAdversary(strength=1.0), "🟢 Channel Tamper", "attack-channel_tamper", "Flips bell outcome bits in transit"),
        "Impersonation": (ImpersonationAdversary(claimed_identity=st.session_state.signer_id, strength=1.0), "🟠 Impersonation", "attack-impersonation", "Fabricates key_id + random ops/outcomes"),
        "PNS": (PNSAdversary(strength=1.0), "🔵 PNS", "attack-pns", "Photon-number-splitting: intercepts k/L copies cleanly"),
        "Collective": (CollectiveAttackAdversary(strength=0.5), "🟣 Collective", "attack-collective", "Joint measurement across L copies, entropy-based mismatch"),
        "Faked-State": (FakedStateAdversary(strength=1.0), "⚪ Faked-State", "attack-faked_state", "Forces detector outcome, zero disturbance"),
        "Time-Shift": (TimeShiftAdversary(strength=1.0), "🟡 Time-Shift", "attack-time_shift", "Exploits detector timing mismatch via timestamp"),
        "Trojan-Horse": (TrojanHorseAdversary(strength=1.0), "🟤 Trojan-Horse", "attack-trojan_horse", "Learns ops via injected light, zero disturbance (hardware defence)"),
        "MitM Classical": (MitmClassicalAdversary(strength=1.0), "🔶 MitM Classical", "attack-mitm_classical", "Tampers real announced ops in transit"),
    }

    # Create attack buttons and capture clicks immediately
    atk_cols = st.columns(5, gap="medium")
    attack_clicked = None
    attack_adv = None

    for i, (label, (adv, display_label, css_class, tooltip)) in enumerate(attack_adversaries.items()):
        with atk_cols[i % 5]:
            st.markdown(f'<div class="{css_class}">', unsafe_allow_html=True)
            clicked = st.button(
                display_label,
                use_container_width=True,
                help=tooltip,
                disabled=st.session_state.last_signature is None,
            )
            st.markdown('</div>', unsafe_allow_html=True)
            if clicked:
                attack_clicked = label
                attack_adv = adv

    st.markdown("---")

    # --- Process Actions ---
    action_taken = False

    if sign_clicked:
        with st.spinner("Signing message..."):
            try:
                sig = sign(message_bits, key, core=st.session_state.quantum_core, config=st.session_state.config)
                st.session_state.last_signature = sig
                result = _run_full_pipeline(sig)
                st.session_state.last_detection = result
                _log_event(sig, result, attack_label=None)
                st.session_state.last_action = "sign"
                st.session_state.action_timestamp = time.time()
                action_taken = True
            except Exception as e:
                st.error(f"❌ Signing failed: {e}")
                _log_event(
                    Signature(
                        sig_id="error",
                        key_id=key.key_id,
                        signer_id=key.signer_id,
                        message=message_bits,
                        declared_ops=(),
                        bell_outcomes=(),
                        nonce="error",
                        timestamp=time.time(),
                    ),
                    DetectionResult(
                        sig_id="error",
                        verdict=Verdict.REJECT,
                        threat=ThreatType.NONE,
                        mismatch_rate=1.0,
                        n_measurements=0,
                        forgery_prob_bound=1.0,
                        chi2_stat=0.0,
                        chi2_p_value=1.0,
                        reason=f"Signing error: {e}",
                        timestamp=time.time(),
                    ),
                    attack_label="Sign (Error)",
                )
                action_taken = True

    if attack_clicked and attack_adv and st.session_state.last_signature is not None:
        with st.spinner(f"Launching {attack_clicked} attack..."):
            try:
                tampered_sig = attack_adv.attack(st.session_state.last_signature)
                # Channel tamper's real signal is through noise_level, not bell_outcomes.
                # Check if the adversary reports a noise_level override.
                nl_override = attack_adv.noise_level_override()
                records = verify(
                    tampered_sig, st.session_state.signer_key,
                    noise_level=nl_override,
                    core=st.session_state.quantum_core,
                    config=st.session_state.config,
                )
                noise_floor = _calibrated_noise_floor(st.session_state.config)
                result = evaluate(records, tampered_sig, st.session_state.seen_nonces, noise_floor=noise_floor)
                st.session_state.seen_nonces.add(tampered_sig.nonce)
                st.session_state.last_detection = result
                _log_event(tampered_sig, result, attack_label=attack_clicked)
                st.session_state.last_action = attack_clicked.lower().replace(" ", "_")
                st.session_state.action_timestamp = time.time()
                action_taken = True
            except Exception as e:
                st.error(f"❌ {attack_clicked} attack failed: {e}")
                _log_event(
                    st.session_state.last_signature,
                    DetectionResult(
                        sig_id=st.session_state.last_signature.sig_id,
                        verdict=Verdict.REJECT,
                        threat=ThreatType.NONE,
                        mismatch_rate=1.0,
                        n_measurements=0,
                        forgery_prob_bound=1.0,
                        chi2_stat=0.0,
                        chi2_p_value=1.0,
                        reason=f"Attack error: {e}",
                        timestamp=time.time(),
                    ),
                    attack_label=f"{attack_clicked} (Error)",
                )
                action_taken = True

    if action_taken:
        st.rerun()

    # --- Results Section ---
    if st.session_state.last_detection is not None:
        st.markdown("### 📊 Detection Result")

        _render_verdict_card(st.session_state.last_detection)
        _render_metrics_row(st.session_state.last_detection)

        with st.expander("🔍 Signature Details (Debug)", expanded=False):
            sig = st.session_state.last_signature
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Identity**")
                st.code(f"sig_id: {sig.sig_id}\nkey_id: {sig.key_id}\nsigner_id: {sig.signer_id}\nnonce: {sig.nonce}")
            with col2:
                st.markdown("**Message & Ops**")
                st.code(f"message: {sig.message}\ndeclared_ops: {[op.value for op in sig.declared_ops]}\nbell_outcomes: {sig.bell_outcomes}")

    # --- Event Log ---
    st.markdown("### 📋 Event Log")

    if st.session_state.event_log:
        df = pd.DataFrame(st.session_state.event_log)

        # Column order
        cols_order = ["time", "attack", "verdict", "threat", "signer", "message", "mismatch", "forgery_bound", "sig_id", "reason"]
        df = df[cols_order]

        def style_verdict(val):
            colors = {
                "accept": "background-color: #d4edda; color: #155724; font-weight: 600;",
                "accept_no_transfer": "background-color: #fff3cd; color: #856404; font-weight: 600;",
                "reject": "background-color: #f8d7da; color: #721c24; font-weight: 600;",
            }
            return colors.get(val, "")

        def style_threat(val):
            colors = {
                "none": "background-color: #d4edda; color: #155724; font-weight: 600;",
                "forgery": "background-color: #f8d7da; color: #721c24; font-weight: 600;",
                "impersonation": "background-color: #ffe0b2; color: #e65100; font-weight: 600;",
                "replay": "background-color: #e1bee7; color: #4a148c; font-weight: 600;",
                "channel_tamper": "background-color: #b2dfdb; color: #00695c; font-weight: 600;",
            }
            return colors.get(val, "")

        def style_attack(val):
            if val == "Legitimate":
                return "background-color: #e7f5ff; color: #0d6efd; font-weight: 600;"
            return "font-weight: 600;"

        styled = (
            df.style
            .map(style_verdict, subset=["verdict"])
            .map(style_threat, subset=["threat"])
            .map(style_attack, subset=["attack"])
            .set_properties(**{
                'font-size': '0.85rem',
                'font-family': 'monospace',
            }, subset=["sig_id", "message"])
            .set_table_styles([
                {'selector': 'th', 'props': [('font-weight', '600'), ('background-color', '#f8f9fa'), ('color', '#495057')]},
                {'selector': 'td', 'props': [('padding', '0.5rem 0.75rem')]},
            ])
        )

        st.dataframe(styled, use_container_width=True, hide_index=True, height=400)
    else:
        st.info("📭 No events yet. Sign a message or launch an attack to populate the log.")

    # --- Evidence Panel: Plots ---
    st.markdown("### 📈 Evidence")

    tab1, tab2, tab3 = st.tabs(["Mismatch History", "Forgery Probability Curve", "Noise Sweep"])

    with tab1:
        if st.session_state.event_log:
            log_df = pd.DataFrame(st.session_state.event_log)
            log_df["mismatch_pct"] = log_df["mismatch"].str.rstrip("%").astype(float)
            log_df["idx"] = range(len(log_df) - 1, -1, -1)

            st.line_chart(
                log_df.set_index("idx")["mismatch_pct"],
                use_container_width=True,
                height=300,
                color="#dc3545",
            )
            st.caption("Mismatch rate per event (newest at top)")
        else:
            st.info("Sign a message or launch an attack to see the mismatch history.")

    with tab2:
        message_length_for_curve = 2
        L_range = np.arange(8, 512, 8)
        p_f = 1e-6
        noise_floor = 0.0

        def hoeffding_s_a(n, nf, pf):
            if n <= 0:
                return 1.0
            margin = math.sqrt(-math.log(pf) / (2.0 * n))
            return min(nf + margin, 1.0)

        # K = message_length * L is the total elements a signature reveals;
        # the number of CONCLUSIVE elements n is ~K/2 (see
        # protocol/verifier.py's "STATE ELIMINATION" docstring).
        s_a_values = [
            hoeffding_s_a(int(message_length_for_curve * l / 2), noise_floor, p_f)
            for l in L_range
        ]

        curve_df = pd.DataFrame({
            "L": L_range,
            "Acceptance Threshold (s_a)": s_a_values,
        })

        st.line_chart(
            curve_df.set_index("L"),
            use_container_width=True,
            height=300,
            color=["#28a745"],
        )
        st.caption("Hoeffding-derived acceptance threshold vs L (message_length=2). Forgery probability ≤ 10⁻⁶")

        # Mark current L, using the ACTIVE key's real message_length and the
        # real measured noise floor (not the curve's illustrative message_length=2
        # / ideal-channel assumptions) so this number matches the threshold
        # evaluate() actually used on the last signature -- CLAUDE.md: s_a/s_v
        # are derived from the measured noise floor and p_f, never hardcoded.
        current_L = st.session_state.config.n_copies
        current_message_length = st.session_state.message_length
        current_noise_floor = _calibrated_noise_floor(st.session_state.config)
        current_n = int(current_message_length * current_L / 2)
        current_s_a = hoeffding_s_a(current_n, current_noise_floor, p_f)
        st.metric("Current L", current_L, help="Your active signature copies")
        st.metric(
            "Current s_a", f"{current_s_a:.3f}",
            help=(
                f"Acceptance threshold at this L, using the active key's "
                f"message_length={current_message_length} and measured noise "
                f"floor={current_noise_floor:.3f} -- matches the threshold "
                f"evaluate() actually applies, not the illustrative curve above."
            ),
        )

    with tab3:
        sweep_L = st.session_state.config.n_copies
        sweep_bases = st.session_state.config.bases
        sweep_cache = st.session_state.setdefault("_noise_sweep_cache", {})
        sweep_cache_key = (sweep_L, sweep_bases)

        if sweep_cache_key not in sweep_cache:
            noise_levels = np.linspace(0.0, 1.0, 11)
            measured_mismatch = []
            sweep_core = M1QuantumCore()
            for nl in noise_levels:
                sweep_config = QDSConfig(
                    n_copies=sweep_L,
                    noise_level=float(nl),
                    bases=sweep_bases,
                )
                sweep_key = keygen(
                    "_noise_sweep", sweep_L, message_length=1,
                    core=sweep_core, config=sweep_config,
                )
                sweep_sig = sign((0,), sweep_key, core=sweep_core, config=sweep_config)
                sweep_records = verify(sweep_sig, sweep_key, core=sweep_core, config=sweep_config)
                measured_mismatch.append(
                    mismatch_rate(sweep_records) * 100 if sweep_records else 0.0
                )
            sweep_cache[sweep_cache_key] = (noise_levels, measured_mismatch)

        noise_levels, measured_mismatch = sweep_cache[sweep_cache_key]

        sweep_df = pd.DataFrame({
            "Noise Level": [f"{nl:.0%}" for nl in noise_levels],
            "Measured Mismatch (%)": measured_mismatch,
        })

        st.line_chart(
            sweep_df.set_index("Noise Level"),
            use_container_width=True,
            height=300,
            color=["#ffc107"],
        )
        st.caption(
            f"Empirically measured mismatch rate vs channel noise level "
            f"(L={sweep_L}, one throwaway keygen/sign/verify per point). "
            "noise_level is a depolarising-channel dial, not the mismatch "
            "rate itself -- see _calibrated_noise_floor()."
        )

    # --- Footer ---
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align: center; color: #6c757d; font-size: 0.85rem; padding: 1rem;">
            SIH26141 — Quantum-Inspired Cyber Threat Detection for QDS &nbsp;|&nbsp;
            No AI/ML in detection path &nbsp;|&nbsp;
            Verdicts from M4 detection engine only &nbsp;|&nbsp;
            Dashboard recomputes nothing
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
