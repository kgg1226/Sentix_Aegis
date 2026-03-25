"""Defense form definitions — Alpha, Beta, Gamma, Delta.

Each form represents a fundamentally different defense topology,
not just parameter tuning. Form switching changes architecture.
"""
from __future__ import annotations
from dataclasses import dataclass
from aegis.common.types import DefenseForm

@dataclass(frozen=True, slots=True)
class FormSpec:
    form: DefenseForm
    name: str
    description: str
    target_densities: dict[str, float]
    pressure_range: tuple[float, float]  # (min, max) threat pressure for this form

FORM_SPECS: dict[DefenseForm, FormSpec] = {
    DefenseForm.ALPHA: FormSpec(
        form=DefenseForm.ALPHA, name="Layered defense",
        description="Classic depth-in-defense. WAF → IDS → app firewall. Low overhead.",
        target_densities={"RTG":0.35,"ISO":0.25,"ATH":0.35,"DTX":0.45,"DCP":0.15,"RSP":0.30},
        pressure_range=(0.0, 0.40),
    ),
    DefenseForm.BETA: FormSpec(
        form=DefenseForm.BETA, name="Distributed mesh",
        description="Every node is sensor + enforcer. No single point of failure.",
        target_densities={"RTG":0.80,"ISO":0.65,"ATH":0.55,"DTX":0.60,"DCP":0.30,"RSP":0.50},
        pressure_range=(0.40, 0.65),
    ),
    DefenseForm.GAMMA: FormSpec(
        form=DefenseForm.GAMMA, name="Deception grid",
        description="Honeypot-first. Funnel attackers into traps. Extract intelligence.",
        target_densities={"RTG":0.40,"ISO":0.35,"ATH":0.40,"DTX":0.70,"DCP":0.85,"RSP":0.45},
        pressure_range=(0.65, 0.85),
    ),
    DefenseForm.DELTA: FormSpec(
        form=DefenseForm.DELTA, name="Zero-trust fortress",
        description="Every request verified independently. Micro-segmented. Max isolation.",
        target_densities={"RTG":0.55,"ISO":0.95,"ATH":0.95,"DTX":0.75,"DCP":0.10,"RSP":0.85},
        pressure_range=(0.85, 1.0),
    ),
}

def recommend_form(pressure: float) -> DefenseForm:
    """Select optimal defense form based on current threat pressure."""
    for form, spec in FORM_SPECS.items():
        lo, hi = spec.pressure_range
        if lo <= pressure <= hi:
            return form
    return DefenseForm.DELTA  # Default to maximum protection
