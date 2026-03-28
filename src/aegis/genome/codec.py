"""144-bit genome encoder/decoder.

Handles serialization, segment extraction, CRC-8 validation,
and construction of known defense form genomes.
"""

from __future__ import annotations

from aegis.common.types import GENOME_BITS, SEGMENTS, DefenseForm, Genome


def _crc8(bits: tuple[int, ...]) -> tuple[int, ...]:
    """Compute CRC-8 over the first 136 bits. Returns 8-bit checksum as tuple."""
    crc = 0x00
    for i in range(0, 136, 8):
        byte_val = 0
        for j in range(8):
            if i + j < 136:
                byte_val = (byte_val << 1) | bits[i + j]
            else:
                byte_val <<= 1
        crc ^= byte_val
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return tuple((crc >> (7 - i)) & 1 for i in range(8))


def validate_checksum(genome: Genome) -> bool:
    """Verify CRC-8 integrity of genome."""
    expected = _crc8(genome.bits)
    actual = genome.segment("CHK")
    return expected == actual


def with_valid_checksum(bits: tuple[int, ...]) -> Genome:
    """Create a genome with correct CRC-8 checksum computed from bits 0-135."""
    if len(bits) < 136:
        msg = f"Need at least 136 bits to compute checksum, got {len(bits)}"
        raise ValueError(msg)
    payload = bits[:136]
    chk = _crc8(payload)
    return Genome(bits=payload + chk)


# ---------------------------------------------------------------------------
# Predefined defense forms
# ---------------------------------------------------------------------------

# Each form has a characteristic bit pattern per segment.
# These are starting points — evolution diverges from them.

_FORM_TEMPLATES: dict[DefenseForm, dict[str, float]] = {
    # Battle-tuned: 3x 1000-battle campaigns. RTG is #1 chronic target.
    # All segments >= 0.75 floor. RTG raised to 0.85 (erode counter).
    DefenseForm.ALPHA: {
        "RTG": 0.85, "ISO": 0.75, "ATH": 0.75,
        "DTX": 0.75, "DCP": 0.75, "RSP": 0.75,
    },
    DefenseForm.BETA: {
        "RTG": 0.85, "ISO": 0.75, "ATH": 0.75,
        "DTX": 0.75, "DCP": 0.75, "RSP": 0.75,
    },
    DefenseForm.GAMMA: {
        "RTG": 0.85, "ISO": 0.75, "ATH": 0.75,
        "DTX": 0.75, "DCP": 0.85, "RSP": 0.75,
    },
    DefenseForm.DELTA: {
        "RTG": 0.85, "ISO": 0.95, "ATH": 0.95,
        "DTX": 0.80, "DCP": 0.75, "RSP": 0.85,
    },
}


def _density_to_bits(density: float, length: int) -> tuple[int, ...]:
    """Convert a target density to a bit pattern of given length."""
    on_count = round(density * length)
    # Spread 1-bits evenly across the segment
    bits = [0] * length
    if on_count > 0:
        step = length / on_count
        for i in range(on_count):
            bits[int(i * step)] = 1
    return tuple(bits)


def _encode_header(form: DefenseForm, version: int = 0) -> tuple[int, ...]:
    """Encode HDR segment: 2-bit form ID + 4-bit version + 2-bit parity placeholder."""
    form_bits = ((form.value >> 1) & 1, form.value & 1)
    ver_bits = tuple((version >> (3 - i)) & 1 for i in range(4))
    parity = (sum(form_bits) + sum(ver_bits)) % 2
    return form_bits + ver_bits + (parity, 0)


def build_form_genome(form: DefenseForm, version: int = 0) -> Genome:
    """Construct a genome for a predefined defense form."""
    template = _FORM_TEMPLATES[form]
    hdr = _encode_header(form, version)

    body_bits: list[int] = []
    for seg_name, offset, length in SEGMENTS:
        if seg_name == "HDR" or seg_name == "CHK":
            continue
        density = template.get(seg_name, 0.5)
        body_bits.extend(_density_to_bits(density, length))

    payload = hdr + tuple(body_bits)
    return with_valid_checksum(payload)


def genome_to_hex(genome: Genome) -> str:
    """Serialize genome to hex string (18 hex chars = 144 bits / 4)."""
    value = 0
    for b in genome.bits:
        value = (value << 1) | b
    return f"{value:036x}"


def hex_to_genome(hex_str: str) -> Genome:
    """Deserialize genome from hex string."""
    value = int(hex_str, 16)
    bits = tuple((value >> (GENOME_BITS - 1 - i)) & 1 for i in range(GENOME_BITS))
    return Genome(bits=bits)
