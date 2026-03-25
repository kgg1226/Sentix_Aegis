# AGENTS.md — Sentix-AEGIS Agent Routing Index

> Single source of truth for multi-agent session separation.
> Each agent reads ONLY the sections relevant to their role.

## Project context

AEGIS (Adaptive Evolving Guard & Immune System) is a self-evolving multi-cloud
security defense. See README.md for full architecture.

## Agent roles

### Planner
- **Scope**: tasks/todo.md, README.md, AGENTS.md, docs/
- **Responsibility**: Break features into tasks, maintain roadmap, review architecture decisions
- **Never touches**: src/, tests/, infra/

### Security agent
- **Scope**: src/aegis/immune/, src/aegis/detection/, src/aegis/sandbox/red_agent.py
- **Responsibility**: LLM injection defense, detection pipeline hardening, Red agent attack strategies
- **Key constraint**: Every detection threshold must be in config.py, never hardcoded

### Backend agent
- **Scope**: src/aegis/genome/, src/aegis/metamorphic/, src/aegis/common/, src/aegis/sandbox/
- **Responsibility**: Genome engine, fitness function, metamorphic transitions, arena orchestration
- **Key constraint**: Genome is immutable (frozen dataclass). All mutations return new instances.

### DevOps agent
- **Scope**: infra/, .github/, pyproject.toml, Dockerfile
- **Responsibility**: AWS CDK, CI/CD, container builds, deployment pipeline
- **Key constraint**: All infra changes go through CDK, no manual AWS console changes

### QA agent
- **Scope**: tests/, src/ (read-only for analysis)
- **Responsibility**: Unit tests, integration tests, property-based testing with hypothesis
- **Key constraint**: Every fitness function defect (AEGIS-F001 through F012) must have a regression test
