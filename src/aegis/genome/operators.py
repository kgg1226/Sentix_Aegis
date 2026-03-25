"""Genetic operators for genome evolution.

All operators return NEW Genome instances — the original is never mutated.
"""

from __future__ import annotations

import random

from aegis.common.types import GENOME_BITS, SEGMENTS, Genome
from aegis.genome.codec import with_valid_checksum


def point_mutation(genome: Genome, *, bit_index: int | None = None) -> Genome:
    """Flip a single bit. If bit_index is None, picks a random non-header bit."""
    if bit_index is None:
        # Exclude HDR (0-7) and CHK (136-143) from random mutation
        bit_index = random.randint(8, 135)
    if not (0 <= bit_index < GENOME_BITS):
        msg = f"bit_index must be in [0, {GENOME_BITS}), got {bit_index}"
        raise ValueError(msg)

    bits = list(genome.bits)
    bits[bit_index] = 1 - bits[bit_index]
    return with_valid_checksum(tuple(bits))


def burst_mutation(genome: Genome, *, count: int = 5) -> Genome:
    """Flip multiple random bits in the payload region (8-135)."""
    bits = list(genome.bits)
    indices = random.sample(range(8, 136), min(count, 128))
    for i in indices:
        bits[i] = 1 - bits[i]
    return with_valid_checksum(tuple(bits))


def crossover(parent_a: Genome, parent_b: Genome, *, segment_name: str | None = None) -> Genome:
    """Replace one segment of parent_a with the corresponding segment from parent_b.

    If segment_name is None, picks a random non-header, non-checksum segment.
    Returns a new genome with valid checksum.
    """
    # Pick segment to swap
    swappable = [name for name, _, _ in SEGMENTS if name not in ("HDR", "CHK")]
    if segment_name is None:
        segment_name = random.choice(swappable)
    if segment_name not in swappable:
        msg = f"Cannot crossover HDR or CHK segment. Choose from: {swappable}"
        raise ValueError(msg)

    # Find segment bounds
    offset, length = 0, 0
    for name, seg_offset, seg_length in SEGMENTS:
        if name == segment_name:
            offset, length = seg_offset, seg_length
            break

    # Splice
    bits = list(parent_a.bits)
    donor_segment = parent_b.bits[offset : offset + length]
    bits[offset : offset + length] = list(donor_segment)

    return with_valid_checksum(tuple(bits))
