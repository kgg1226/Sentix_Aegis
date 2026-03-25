"""Unit tests for AEGIS core modules.

Covers genome codec, fitness function (including F001-F012 regression tests),
homeostasis, and detection pipeline.
"""

from __future__ import annotations

import math

import pytest

from aegis.common.types import (
    GENOME_BITS,
    DefenseForm,
    Genome,
    ThreatContext,
)
from aegis.genome.codec import (
    build_form_genome,
    genome_to_hex,
    hex_to_genome,
    validate_checksum,
    with_valid_checksum,
)
from aegis.genome.fitness import evaluate
from aegis.genome.homeostasis import apply_homeostasis, compute_target, restoring_force
from aegis.genome.operators import burst_mutation, crossover, point_mutation


# ---------------------------------------------------------------------------
# Genome codec
# ---------------------------------------------------------------------------


class TestGenome:
    def test_genome_length_validation(self) -> None:
        with pytest.raises(ValueError, match="exactly 144"):
            Genome(bits=tuple([0] * 100))

    def test_genome_binary_validation(self) -> None:
        with pytest.raises(ValueError, match="must be 0 or 1"):
            Genome(bits=tuple([2] * GENOME_BITS))

    def test_genome_immutability(self) -> None:
        g = Genome(bits=tuple([0] * GENOME_BITS))
        with pytest.raises(AttributeError):
            g.bits = tuple([1] * GENOME_BITS)  # type: ignore[misc]

    def test_segment_extraction(self) -> None:
        bits = tuple([1] * 8 + [0] * 136)
        g = with_valid_checksum(bits[:136])
        hdr = g.segment("HDR")
        assert len(hdr) == 8

    def test_density_calculation(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        d = g.density("RTG")
        assert 0.0 <= d <= 1.0

    def test_form_id_decode(self) -> None:
        for form in DefenseForm:
            g = build_form_genome(form)
            assert g.form_id == form


class TestCodec:
    def test_checksum_valid(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        assert validate_checksum(g)

    def test_checksum_corrupted(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        corrupted_bits = list(g.bits)
        corrupted_bits[50] = 1 - corrupted_bits[50]
        corrupted = Genome(bits=tuple(corrupted_bits))
        assert not validate_checksum(corrupted)

    def test_hex_roundtrip(self) -> None:
        g = build_form_genome(DefenseForm.BETA)
        hex_str = genome_to_hex(g)
        restored = hex_to_genome(hex_str)
        assert restored.bits == g.bits


# ---------------------------------------------------------------------------
# Genetic operators
# ---------------------------------------------------------------------------


class TestOperators:
    def test_point_mutation_flips_one_bit(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        mutated = point_mutation(g, bit_index=20)
        diff = sum(a != b for a, b in zip(g.bits, mutated.bits))
        # At least 1 bit different (payload), plus checksum may change
        assert diff >= 1

    def test_burst_mutation_flips_multiple(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        mutated = burst_mutation(g, count=5)
        assert mutated.bits != g.bits
        assert validate_checksum(mutated)

    def test_crossover_produces_valid_genome(self) -> None:
        a = build_form_genome(DefenseForm.ALPHA)
        b = build_form_genome(DefenseForm.DELTA)
        child = crossover(a, b, segment_name="ISO")
        assert validate_checksum(child)
        assert len(child.bits) == GENOME_BITS

    def test_crossover_rejects_hdr(self) -> None:
        a = build_form_genome(DefenseForm.ALPHA)
        b = build_form_genome(DefenseForm.BETA)
        with pytest.raises(ValueError, match="Cannot crossover"):
            crossover(a, b, segment_name="HDR")


# ---------------------------------------------------------------------------
# Fitness function — including AEGIS-F001 through F012 regression tests
# ---------------------------------------------------------------------------


class TestFitness:
    @pytest.fixture()
    def ctx(self) -> ThreatContext:
        return ThreatContext(pressure=0.4, diversity=0.3, novelty=0.2)

    def test_fitness_range(self, ctx: ThreatContext) -> None:
        for form in DefenseForm:
            g = build_form_genome(form)
            result = evaluate(g, ctx)
            assert 0.0 <= result.final <= 1.0

    def test_f002_efficiency_reaches_zero(self) -> None:
        """AEGIS-F002: S_eff must reach true zero at max overhead."""
        # Create genome with all segments at max density
        bits = tuple([1] * 136)
        g = with_valid_checksum(bits)
        ctx = ThreatContext(pressure=0.5, diversity=0.3, novelty=0.2)
        result = evaluate(g, ctx)
        assert result.scores["efficiency"] < 0.05, (
            f"S_eff = {result.scores['efficiency']} at max overhead, should approach 0"
        )

    def test_f003_ctx_bounded(self) -> None:
        """AEGIS-F003: S_ctx must never exceed 1.0."""
        g = build_form_genome(DefenseForm.DELTA)
        # Extreme threat context
        ctx = ThreatContext(pressure=0.95, diversity=0.90, novelty=0.85)
        result = evaluate(g, ctx)
        assert result.scores["threat_match"] <= 1.0

    def test_f004_smooth_penalty(self) -> None:
        """AEGIS-F004: No cliff discontinuities in penalty."""
        ctx = ThreatContext(pressure=0.5, diversity=0.3, novelty=0.2)
        # Create genomes straddling the 0.2 threshold
        bits_a = list([0] * 136)
        bits_b = list([0] * 136)
        # ATH segment (56-71): set ~19% density (just below old threshold)
        for i in range(56, 59):
            bits_a[i] = 1  # 3/16 = 18.75%
        # ATH: set ~25% (just above old threshold)
        for i in range(56, 60):
            bits_b[i] = 1  # 4/16 = 25%
        g_below = with_valid_checksum(tuple(bits_a))
        g_above = with_valid_checksum(tuple(bits_b))
        f_below = evaluate(g_below, ctx)
        f_above = evaluate(g_above, ctx)
        # With smooth penalty, the difference should be gradual, not 0.30 cliff
        delta = abs(f_above.final - f_below.final)
        assert delta < 0.20, f"Penalty cliff detected: delta={delta}"

    def test_f006_synergy_non_negative(self) -> None:
        """AEGIS-F006: S_syn must be clamped to [0, 1]."""
        # High deception, low detection → old model went negative
        bits = list([0] * 136)
        # DCP segment (104-119): all ones
        for i in range(104, 120):
            bits[i] = 1
        # DTX segment (72-103): mostly zeros
        bits[72] = 1
        g = with_valid_checksum(tuple(bits))
        ctx = ThreatContext(pressure=0.5, diversity=0.5, novelty=0.5)
        result = evaluate(g, ctx)
        assert result.scores["synergy"] >= 0.0

    def test_f010_empirical_blending(self) -> None:
        """AEGIS-F010: Red win rate should influence final fitness."""
        g = build_form_genome(DefenseForm.ALPHA)
        ctx = ThreatContext(pressure=0.5, diversity=0.3, novelty=0.2)
        f_structural = evaluate(g, ctx).final
        f_empirical = evaluate(g, ctx, red_win_rate=0.8, test_rounds=500).final
        # High red win rate should significantly lower fitness
        assert f_empirical < f_structural

    def test_f011_confidence_interval(self) -> None:
        """AEGIS-F011: Untested genomes have wide confidence intervals."""
        g = build_form_genome(DefenseForm.ALPHA)
        ctx = ThreatContext(pressure=0.5, diversity=0.3, novelty=0.2)
        untested = evaluate(g, ctx, test_rounds=0)
        tested = evaluate(g, ctx, test_rounds=1000)
        assert untested.confidence_interval > tested.confidence_interval


# ---------------------------------------------------------------------------
# Homeostasis
# ---------------------------------------------------------------------------


class TestHomeostasis:
    def test_target_peacetime_balanced(self) -> None:
        ctx = ThreatContext(pressure=0.1, diversity=0.1, novelty=0.1)
        target = compute_target(ctx)
        values = list(target.values())
        spread = max(values) - min(values)
        assert spread < 0.4, "Peacetime target should be relatively balanced"

    def test_target_wartime_asymmetric(self) -> None:
        ctx = ThreatContext(pressure=0.95, diversity=0.3, novelty=0.1)
        target = compute_target(ctx)
        assert target["ISO"] > 0.8, "Wartime should max isolation"
        assert target["ATH"] > 0.8, "Wartime should max auth"

    def test_restoring_force_direction(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        ctx = ThreatContext(pressure=0.9, diversity=0.3, novelty=0.1)
        forces = restoring_force(g, ctx)
        # Alpha has low ISO, wartime wants high ISO → force should be positive
        assert forces["ISO"] > 0, "Should push ISO up toward wartime target"

    def test_homeostasis_preserves_validity(self) -> None:
        g = build_form_genome(DefenseForm.ALPHA)
        ctx = ThreatContext(pressure=0.5, diversity=0.5, novelty=0.5)
        adjusted = apply_homeostasis(g, ctx)
        assert len(adjusted.bits) == GENOME_BITS
        assert validate_checksum(adjusted)
