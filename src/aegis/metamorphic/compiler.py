"""Genome → topology compiler.

Translates a 144-bit genome into concrete defense topology configuration
that can be applied to the live environment.
"""
from __future__ import annotations
from dataclasses import dataclass
from aegis.common.types import Genome

@dataclass(frozen=True, slots=True)
class TopologyConfig:
    routing_mode: str          # linear | partial_mesh | full_mesh
    isolation_level: str       # vpc | subnet | service | request
    auth_mode: str             # perimeter | token | mtls | zero_trust
    sensor_coverage: float     # 0.0-1.0
    honeypot_count: int        # Number of active honeypots
    response_mode: str         # monitor | rate_limit | block | auto_isolate

def compile_genome(genome: Genome) -> TopologyConfig:
    """Compile genome into deployable topology configuration."""
    rtg_d = genome.density("RTG")
    iso_d = genome.density("ISO")
    ath_d = genome.density("ATH")
    dtx_d = genome.density("DTX")
    dcp_d = genome.density("DCP")
    rsp_d = genome.density("RSP")

    routing = "full_mesh" if rtg_d > 0.7 else ("partial_mesh" if rtg_d > 0.4 else "linear")
    isolation = ("request" if iso_d > 0.8 else "service" if iso_d > 0.5
                 else "subnet" if iso_d > 0.25 else "vpc")
    auth = ("zero_trust" if ath_d > 0.75 else "mtls" if ath_d > 0.5
            else "token" if ath_d > 0.25 else "perimeter")
    honeypots = round(dcp_d * 16)
    response = ("auto_isolate" if rsp_d > 0.75 else "block" if rsp_d > 0.5
                else "rate_limit" if rsp_d > 0.25 else "monitor")

    return TopologyConfig(
        routing_mode=routing, isolation_level=isolation, auth_mode=auth,
        sensor_coverage=round(dtx_d, 3), honeypot_count=honeypots,
        response_mode=response,
    )
