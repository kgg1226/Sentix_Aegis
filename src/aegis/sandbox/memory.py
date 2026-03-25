"""Attack pattern memory bank.

Stores attack fingerprints as vectors for similarity matching.
In production: pgvector. Here: in-memory for testing.
"""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, field

@dataclass(frozen=True, slots=True)
class AttackFingerprint:
    vector_hash: str
    category: str
    target_segment: str
    success: bool
    round_num: int

class MemoryBank:
    def __init__(self) -> None:
        self._fingerprints: list[AttackFingerprint] = []

    def record(self, attack_data: dict, success: bool, round_num: int) -> AttackFingerprint:
        raw = json.dumps(attack_data, sort_keys=True, default=str)
        h = hashlib.sha256(raw.encode()).hexdigest()[:32]
        fp = AttackFingerprint(
            vector_hash=h, category=attack_data.get("category","unknown"),
            target_segment=attack_data.get("target_segment","unknown"),
            success=success, round_num=round_num,
        )
        self._fingerprints.append(fp)
        return fp

    def find_similar(self, attack_data: dict, top_k: int = 5) -> list[AttackFingerprint]:
        # Simplified: exact category match. Production: cosine similarity on embeddings.
        cat = attack_data.get("category", "")
        matches = [fp for fp in self._fingerprints if fp.category == cat]
        return sorted(matches, key=lambda f: f.round_num, reverse=True)[:top_k]

    @property
    def size(self) -> int:
        return len(self._fingerprints)
