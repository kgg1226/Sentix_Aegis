# AEGIS — Adaptive Evolving Guard & Immune System

> Autonomous multi-cloud security defense that evolves faster than attackers can adapt.

Part of the [Sentix](https://github.com/kgg1226/sentix) ecosystem by JANUS Team.

## Overview

AEGIS is a self-evolving, metamorphic security defense system designed for multi-cloud environments (AWS, Azure, Oracle Cloud). Instead of relying on static rules that attackers learn to bypass, AEGIS encodes its entire defense topology as a 144-bit **genome** that mutates in milliseconds, switches between fundamentally different defense **forms**, and continuously stress-tests itself in a sandboxed **Red vs Blue arena**.

### Core concepts

- **Genome engine** — Defense topology encoded as 144-bit binary genome (7 segments: HDR, RTG, ISO, ATH, DTX, DCP, RSP, CHK). Genetic operations (point mutation, burst mutation, crossover) produce new defense configurations.
- **Metamorphic engine** — Four defense forms (Alpha/Beta/Gamma/Delta) with instant topology switching. The system doesn't just tune parameters — it changes its fundamental architecture.
- **Fitness function** — Multi-objective evaluation: coverage, efficiency, adaptability, synergy, threat-context match. Drives genome evolution through Pareto-optimal selection.
- **Adaptive homeostasis** — Context-aware balance restoration. The "center of gravity" moves with the threat landscape, preventing both pathological drift and counterproductive normalization.
- **Detection pipeline (L0–L5)** — Six-layer detection from sub-millisecond pattern matching to LLM-powered behavioral analysis, plus a dedicated LLM injection immune layer.
- **Sandbox arena** — Isolated environment where Red agent (attacker AI) and Blue agent (defender AI) continuously battle. Winning strategies feed back into the live system.

### Design principles

1. **Human intervention at 3 points only**: request input, critical security decisions, manual deploy approval.
2. **The fitness function is not the truth** — empirical Red/Blue battle outcomes override structural analysis.
3. **Every constant must be calibrated** — no magic numbers without data backing.
4. **The detector must not become the attack surface** — L5 exists to protect L3/L4 from LLM injection.

## Tech stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.12+ | Core engine |
| Async runtime | asyncio | Event-driven pipeline |
| ML inference | AWS Bedrock (Haiku / Sonnet) | L3 behavioral analysis, L4 correlation |
| Event bus | AWS EventBridge | Signal routing |
| Compute | AWS Lambda | L1/L2 fast-path, L5 sidecar |
| Container | AWS ECS Fargate | Sandbox arena isolation |
| Vector store | PostgreSQL + pgvector | Attack memory bank |
| IaC | AWS CDK (Python) | Infrastructure as code |
| Testing | pytest + hypothesis | Property-based testing |
| CI/CD | GitHub Actions | Sentix multi-agent workflow |

## Project structure

```
sentix-aegis/
├── LICENSE                  # Apache 2.0
├── README.md                # This file (SSoT)
├── AGENTS.md                # Multi-agent routing index
├── pyproject.toml           # Dependencies + build config
├── src/
│   └── aegis/
│       ├── __init__.py
│       ├── common/          # Shared types, config, logging
│       │   ├── __init__.py
│       │   ├── types.py     # Core data models
│       │   └── config.py    # Environment + runtime config
│       ├── detection/       # L0-L5 detection pipeline
│       │   ├── __init__.py
│       │   ├── pipeline.py  # Orchestrator
│       │   ├── collectors/  # L0: multi-cloud signal collection
│       │   │   ├── __init__.py
│       │   │   ├── aws.py       # CloudTrail, GuardDuty, SecurityHub
│       │   │   ├── azure.py    # Sentinel, Defender for Cloud
│       │   │   └── oracle.py   # Cloud Guard
│       │   └── analyzers/   # L1-L4 analysis layers
│       │       ├── __init__.py
│       │       ├── pattern.py      # L1: signature matching
│       │       ├── statistical.py  # L2: anomaly detection
│       │       ├── behavioral.py   # L3: LLM behavioral analysis
│       │       └── correlator.py   # L4: cross-cloud correlation
│       ├── immune/          # L5: LLM injection defense
│       │   ├── __init__.py
│       │   ├── canary.py    # Canary token system
│       │   ├── classifier.py # Semantic intent classifier
│       │   └── verifier.py  # Dual-LLM verification
│       ├── genome/          # Genome engine
│       │   ├── __init__.py
│       │   ├── codec.py     # 144-bit encode/decode
│       │   ├── fitness.py   # Multi-objective fitness function
│       │   ├── operators.py # Mutation, crossover operators
│       │   └── homeostasis.py # Adaptive balance restoration
│       ├── metamorphic/     # Metamorphic engine
│       │   ├── __init__.py
│       │   ├── forms.py     # Alpha/Beta/Gamma/Delta definitions
│       │   ├── compiler.py  # Genome → topology compilation
│       │   └── transition.py # Blue-green form switching
│       └── sandbox/         # Red vs Blue arena
│           ├── __init__.py
│           ├── red_agent.py
│           ├── blue_agent.py
│           ├── arena.py     # Battle loop orchestrator
│           └── memory.py    # Attack pattern vector store
├── tests/
│   ├── unit/
│   └── integration/
├── infra/                   # AWS CDK infrastructure (stub — Phase 7)
│   ├── __init__.py
│   ├── app.py              # CDK app entry point
│   └── cdk.json            # CDK configuration
├── docs/                    # Design documents
└── tasks/
    ├── todo.md
    └── lessons.md
```

## Coding conventions

- **Type hints everywhere** — all function signatures must have full type annotations.
- **Dataclasses for data, protocols for interfaces** — no abstract base classes.
- **async by default** — detection pipeline is fully async. Use `asyncio.TaskGroup` for concurrency.
- **Immutable genome** — `Genome` is a frozen dataclass. Mutations return new instances.
- **Confidence as float [0.0, 1.0]** — never use percentages internally. Display layer converts.
- **All thresholds in config** — no magic numbers in business logic.
- **Logging** — structured JSON via `structlog`. Every detection event gets a correlation ID.

## Environment variables

```env
AEGIS_ENV=development|staging|production
AEGIS_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR
AWS_REGION=ap-northeast-2
BEDROCK_MODEL_HAIKU=claude-haiku-4-5-20251001
BEDROCK_MODEL_SONNET=claude-sonnet-4-6
PGVECTOR_URL=postgresql://...
EVENTBRIDGE_BUS_NAME=aegis-events
```

## Getting started

```bash
# Clone
git clone https://github.com/kgg1226/sentix-aegis.git
cd sentix-aegis

# Install (requires Python 3.12+)
pip install -e ".[dev]"

# Run tests
pytest

# Run detection pipeline (local mode)
python -m aegis.detection.pipeline --mode local
```

## Cloud collector setup (optional)

Collectors gracefully degrade when their SDK is not installed — AEGIS runs in local mode without any cloud dependency.

```bash
# AWS (CloudTrail, GuardDuty, SecurityHub) — included in base dependencies
pip install boto3

# Azure (Sentinel, Defender for Cloud)
pip install azure-identity azure-mgmt-securityinsight

# Oracle Cloud (Cloud Guard)
pip install oci
```

Enable/disable collectors via `CollectorConfig` or environment:

| Collector | Default | Config key |
|---|---|---|
| AWS | enabled | `aws_enabled` |
| Azure | disabled | `azure_enabled` + `azure_subscription_id` |
| Oracle | disabled | `oracle_enabled` + `oracle_compartment_id` |

## Known limitations (v0.1)

- Fitness function constants are hand-tuned, not empirically calibrated (see AEGIS-F007).
- Detection pipeline L3/L4 require AWS Bedrock access — local mode uses mock LLM responses.
- Sandbox arena is single-threaded; Red/Blue agents run sequentially, not in parallel.
- AWS CDK infrastructure is stubbed (Phase 7) — deploy stacks are not yet defined.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
