"""Tests for the genome engine: codec, operators, fitness, homeostasis."""

from __future__ import annotations

from aegis.common.types import DefenseForm, Genome, ThreatContext
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
# Codec
# ---------------------------------------------------------------------------

class TestGenomeCodec:
    def test_build_form_genome_produces_valid_checksum(self) -> None:
        for form in DefenseForm:
            genome = build_form_genome(form)
            assert validate_checksum(genome), f"{form.name} genome failed checksum"

    def test_build_form_genome_correct_form_id(self) -> None:
        for form in DefenseForm:
            genome = build_form_genome(form)
            assert genome.form_id == form

    def test_hex_roundtrip(self) -> None:
        original = build_form_genome(DefenseForm.ALPHA)
        hex_str = genome_to_hex(original)
        restored = hex_to_genome(hex_str)
        assert original.bits == restored.bits

    def test_genome_immutability(self) -> None:
        genome = build_form_genome(DefenseForm.ALPHA)
        try:
            genome.bits = (0,) * 144  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass

    def test_genome_rejects_wrong_length(self) -> None:
        try:
            Genome(bits=(0,) * 100)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_genome_rejects_non_binary(self) -> None:
        try:
            Genome(bits=(0, 1, 2) + (0,) * 141)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

class TestOperators:
    def test_point_mutation_flips_one_bit(self) -> None:
        genome = build_form_genome(DefenseForm.ALPHA)
        mutant = point_mutation(genome, bit_index=50)
        diff = sum(a != b for a, b in zip(genome.bits, mutant.bits))
        # Checksum bits may also change, so diff could be > 1
        assert diff >= 1
        assert genome.bits[50] != mutant.bits[50]

    def test_point_mutation_preserves_checksum(self) -> None:
        genome = build_form_genome(DefenseForm.BETA)
        mutant = point_mutation(genome)
        assert validate_checksum(mutant)

    def test_burst_mutation_flips_multiple_bits(self) -> None:
        genome = build_form_genome(DefenseForm.ALPHA)
        mutant = burst_mutation(genome, count=5)
        # At least some payload bits should differ
        payload_diff = sum(
            a != b for a, b in zip(genome.bits[8:136], mutant.bits[8:136])
        )
        assert payload_diff >= 1
        assert validate_checksum(mutant)

    def test_crossover_preserves_checksum(self) -> None:
        alpha = build_form_genome(DefenseForm.ALPHA)
        delta = build_form_genome(DefenseForm.DELTA)
        child = crossover(alpha, delta, segment_name="ISO")
        assert validate_checksum(child)

    def test_crossover_replaces_segment(self) -> None:
        alpha = build_form_genome(DefenseForm.ALPHA)
        delta = build_form_genome(DefenseForm.DELTA)
        child = crossover(alpha, delta, segment_name="ISO")
        # Child's ISO segment should come from delta
        assert child.segment("ISO") == delta.segment("ISO")
        # Other segments should come from alpha
        assert child.segment("RTG") == alpha.segment("RTG")


# ---------------------------------------------------------------------------
# Fitness — regression tests for AEGIS-F001 through F012
# ---------------------------------------------------------------------------

class TestFitness:
    def _default_ctx(self) -> ThreatContext:
        return ThreatContext(pressure=0.4, diversity=0.3, novelty=0.2)

    def test_fitness_range(self) -> None:
        """All fitness values must be in [0.0, 1.0]."""
        ctx = self._default_ctx()
        for form in DefenseForm:
            genome = build_form_genome(form)
            result = evaluate(genome, ctx)
            assert 0.0 <= result.final <= 1.0, f"{form.name}: fitness={result.final}"
            for name, score in result.scores.items():
                assert 0.0 <= score <= 1.0, f"{form.name}/{name}: {score}"

    def test_f002_efficiency_reaches_zero(self) -> None:
        """AEGIS-F002: S_eff must reach 0 at max overhead."""
        # Build a genome with all segments maxed out
        bits = (0,) * 8 + (1,) * 128 + (0,) * 8
        genome = with_valid_checksum(bits)
        ctx = self._default_ctx()
        result = evaluate(genome, ctx)
        # Efficiency should be very low (near zero)
        assert result.scores["efficiency"] < 0.10

    def test_f003_ctx_never_exceeds_one(self) -> None:
        """AEGIS-F003: S_ctx must be clamped to [0, 1]."""
        ctx = ThreatContext(pressure=0.9, diversity=0.8, novelty=0.7)
        for form in DefenseForm:
            genome = build_form_genome(form)
            result = evaluate(genome, ctx)
            assert result.scores["threat_match"] <= 1.0

    def test_f004_smooth_penalty(self) -> None:
        """AEGIS-F004: No cliff discontinuity at thresholds."""
        ctx = self._default_ctx()
        genome_a = build_form_genome(DefenseForm.ALPHA)
        # Evaluate at slightly different ATH densities
        # (can't easily control density, but fitness should vary smoothly)
        results = []
        for _ in range(10):
            mutant = point_mutation(genome_a)
            result = evaluate(mutant, ctx)
            results.append(result.penalty)
        # Penalties should not have extreme jumps between similar genomes
        for i in range(1, len(results)):
            assert abs(results[i] - results[i - 1]) < 0.35

    def test_f006_synergy_non_negative(self) -> None:
        """AEGIS-F006: S_syn must be >= 0."""
        ctx = self._default_ctx()
        for form in DefenseForm:
            genome = build_form_genome(form)
            result = evaluate(genome, ctx)
            assert result.scores["synergy"] >= 0.0

    def test_f010_empirical_blending(self) -> None:
        """AEGIS-F010: Empirical Red win rate modifies fitness."""
        ctx = self._default_ctx()
        genome = build_form_genome(DefenseForm.ALPHA)

        result_no_empirical = evaluate(genome, ctx)
        result_with_empirical = evaluate(genome, ctx, red_win_rate=0.8, test_rounds=500)

        # High red win rate should lower fitness
        assert result_with_empirical.final < result_no_empirical.final

    def test_f011_confidence_interval(self) -> None:
        """AEGIS-F011: CI narrows with more test rounds."""
        ctx = self._default_ctx()
        genome = build_form_genome(DefenseForm.ALPHA)

        ci_0 = evaluate(genome, ctx, test_rounds=0).confidence_interval
        ci_100 = evaluate(genome, ctx, test_rounds=100).confidence_interval
        ci_10000 = evaluate(genome, ctx, test_rounds=10000).confidence_interval

        assert ci_0 > ci_100 > ci_10000


# ---------------------------------------------------------------------------
# Homeostasis
# ---------------------------------------------------------------------------

class TestHomeostasis:
    def test_peacetime_target_is_balanced(self) -> None:
        ctx = ThreatContext(pressure=0.0, diversity=0.0, novelty=0.0)
        target = compute_target(ctx)
        values = list(target.values())
        spread = max(values) - min(values)
        assert spread < 0.40  # Relatively balanced

    def test_wartime_target_is_skewed(self) -> None:
        ctx = ThreatContext(pressure=1.0, diversity=0.0, novelty=0.0)
        target = compute_target(ctx)
        # ISO and ATH should be very high
        assert target["ISO"] > 0.70
        assert target["ATH"] > 0.70

    def test_homeostasis_moves_toward_target(self) -> None:
        ctx = ThreatContext(pressure=0.0, diversity=0.0, novelty=0.0)
        target = compute_target(ctx)

        # Start with a Delta genome (wartime) in peacetime context
        genome = build_form_genome(DefenseForm.DELTA)
        adjusted = apply_homeostasis(genome, ctx)

        # Adjusted genome's ISO density should be lower than original
        # (moving toward peacetime target)
        assert adjusted.density("ISO") <= genome.density("ISO")

    def test_restoring_force_is_nonlinear(self) -> None:
        ctx = ThreatContext(pressure=0.5, diversity=0.3, novelty=0.2)
        genome = build_form_genome(DefenseForm.ALPHA)
        forces = restoring_force(genome, ctx)

        # Forces should exist and not all be zero
        assert any(abs(f) > 0.001 for f in forces.values())
