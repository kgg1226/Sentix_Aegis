# AEGIS — Adaptive Evolving Guard & Immune System

> 해커보다 빠르게 스스로 진화하는 보안 방어 시스템
> A security defense system that evolves faster than hackers can adapt

[Sentix](https://github.com/kgg1226/sentix) 생태계의 일부 · Part of the Sentix ecosystem by JANUS Team.

---

## 이게 뭐야? / What is this?

클라우드 서버(AWS, Azure, Oracle)를 해커로부터 지키는 프로그램이에요.

보통 보안 시스템은 "이런 공격이 오면 이렇게 막아라"라는 **고정된 규칙**을 씁니다.
문제는 해커들이 그 규칙을 알아내면 뚫린다는 거예요.

AEGIS는 다르게 동작합니다:
- 방어 설정을 **DNA(유전자)** 처럼 만들어서, 밀리초마다 변형합니다
- 공격 AI vs 방어 AI가 계속 **모의 전투**를 하면서 약점을 찾고 보완합니다
- 사람이 직접 규칙을 쓸 필요 없이, **스스로 더 강해집니다**

쉽게 말하면: 우리 몸의 **면역 체계**처럼, 새로운 바이러스(해킹)를 만나면 알아서 항체(방어)를 만들어내는 시스템이에요.

---

A program that protects cloud servers (AWS, Azure, Oracle) from hackers.

Normal security systems use **fixed rules** like "if this attack comes, block it this way."
The problem? Once hackers figure out those rules, they break through.

AEGIS works differently:
- It encodes defense settings as **DNA (genome)** and mutates them every millisecond
- An attacker AI and a defender AI constantly **battle each other** to find and fix weaknesses
- No need for humans to write rules — it **gets stronger on its own**

Think of it like your body's **immune system**: when a new virus (hack) appears, it creates antibodies (defenses) automatically.

---

## 어떻게 동작해? / How does it work?

### 1. Genome Engine (유전자 엔진)

방어 설정 전체를 144비트짜리 **유전자 코드**로 표현해요.
유전자 안에는 7가지 정보가 들어있어요:

The entire defense setup is encoded as a 144-bit **genome**.
It contains 7 pieces of information:

| 세그먼트 / Segment | 뭐 하는 거? / What it does |
|---|---|
| HDR | 어떤 방어 형태인지 (알파/베타/감마/델타) · Which defense form (Alpha/Beta/Gamma/Delta) |
| RTG | 네트워크 길을 어떻게 짤지 · How network routes are set up |
| ISO | 구역을 얼마나 철저히 나눌지 · How strictly zones are separated |
| ATH | 누구를 통과시킬지 (인증) · Who gets to pass (authentication) |
| DTX | 감시 센서를 어디에 놓을지 · Where to place detection sensors |
| DCP | 가짜 미끼(허니팟)를 어디에 놓을지 · Where to place decoy traps (honeypots) |
| RSP | 위협 발견 시 어떻게 대응할지 · How to respond when threats are found |
| CHK | 유전자가 망가지지 않았는지 검증 · Checksum to verify genome integrity |

이 유전자는 **절대 직접 수정 안 됩니다** (냉동 보관!). 변형이 필요하면 항상 **새로운 복사본**을 만들어요.

The genome is **never modified directly** (it's frozen!). When mutation is needed, a **new copy** is always created.

### 2. Detection Pipeline (탐지 파이프라인)

6단계로 수상한 활동을 잡아내요. 쉬운 것부터 먼저 체크하고, 진짜 수상하면 깊이 분석해요.

Catches suspicious activity in 6 layers. Checks easy stuff first, then digs deeper if it's really suspicious.

| 단계 / Layer | 뭐 하는 거? / What it does | 속도 / Speed |
|---|---|---|
| L0 | 클라우드에서 이벤트 수집 · Collect events from clouds | 2ms |
| L1 | 알려진 공격 패턴 대조 · Match known attack patterns | <1ms |
| L2 | 통계적으로 이상한 점 찾기 · Find statistical anomalies | 5ms |
| L3 | AI가 행동 의도를 분석 · AI analyzes behavioral intent | 50-200ms |
| L4 | 여러 클라우드 간 연결 고리 찾기 · Find cross-cloud correlations | 100-500ms |
| L5 | AI 자체가 해킹당하지 않게 보호 · Protect the AI itself from being hacked | 병렬 실행 / Runs in parallel |

- L3는 L1/L2 결과가 0.05 이상일 때만 실행 (전투 튜닝: 0.15에서 하향)
- L4는 L3 결과가 0.30 이상일 때만 실행
- L5는 항상 실행 — L3/L4의 AI가 해킹당하는 걸 감시해요

### 3. Metamorphic Engine (변형 엔진)

4가지 완전히 다른 방어 형태 사이를 전환할 수 있어요.
옷을 갈아입듯이, 상황에 따라 방어 체계 전체를 바꿔요.

Can switch between 4 completely different defense forms.
Like changing clothes — swaps the entire defense setup based on the situation.

| 형태 / Form | 특징 / Character |
|---|---|
| Alpha | 평시 기본 방어 · Peacetime default defense |
| Beta | 감시 강화 · Enhanced monitoring |
| Gamma | 격리 중심 · Isolation-focused |
| Delta | 전시 최대 방어 · Wartime maximum defense |

### 4. Sandbox Arena (모의 전투장)

- **Red Agent (공격 AI)**: 6가지 전략 (exploit/probe/blitz/pivot/erode/cascade)으로 약점 공격
- **Blue Agent (방어 AI)**: 6가지 전략 (repair/fortify/diversify/harden/rotate/reinforce)으로 방어 진화
- 5세대 x 1000전 x 3라운드 군비경쟁을 통해 실시간으로 보안 모델 개선
- Red Q4 승률: 56% -> 10%로 감소 (5세대 진화 결과)

- **Red Agent (attacker AI)**: 6 strategies (exploit/probe/blitz/pivot/erode/cascade) targeting weaknesses
- **Blue Agent (defender AI)**: 6 strategies (repair/fortify/diversify/harden/rotate/reinforce) evolving defenses
- Security model improved in real-time through 5 generations x 1000 battles x 3 rounds
- Red Q4 win rate: 56% -> 10% across 5 generations of arms race

### 5. Adaptive Homeostasis (적응형 균형 장치)

전쟁 중에는 방어를 한쪽으로 쏠리게 하는 게 맞아요 (방탄조끼를 입는 것처럼).
하지만 평화로울 때는 균형 잡힌 방어가 좋아요.

이 장치는 **상황에 따라 "정상"의 기준을 바꿔요**. 전쟁 중에 무리하게 균형을 잡으려고 방탄조끼를 벗기지 않아요.

During a war, it makes sense to lean heavily on defense (like wearing armor).
But during peace, balanced defense is better.

This system **moves the definition of "normal" based on the situation**. It won't try to force balance during a war and take off your armor.

---

## 설계 원칙 / Design Principles

1. **사람은 3곳에서만 개입**: 요청 입력, 중요 보안 결정, 배포 승인
2. **점수가 진실이 아니다** — 실전(Red vs Blue) 결과가 이론적 점수보다 우선
3. **모든 숫자에 근거가 있어야 한다** — 감으로 정한 숫자 금지
4. **감지기가 공격 대상이 되면 안 된다** — L5가 L3/L4를 보호

1. **Humans intervene at only 3 points**: request input, critical security decisions, deploy approval
2. **Scores are not the truth** — real battle results override theoretical scores
3. **Every number must have evidence** — no numbers based on gut feeling
4. **The detector must not become a target** — L5 protects L3/L4

---

## 기술 스택 / Tech Stack

| 항목 / Layer | 기술 / Technology | 용도 / Purpose |
|---|---|---|
| 언어 / Language | Python 3.12+ | 핵심 엔진 · Core engine |
| 비동기 / Async | asyncio | 이벤트 기반 파이프라인 · Event-driven pipeline |
| AI 추론 / ML | AWS Bedrock (Haiku / Sonnet) | L3 행동 분석, L4 상관 분석 · Behavioral & correlation analysis |
| 이벤트 버스 / Event bus | AWS EventBridge | 신호 라우팅 · Signal routing |
| 컴퓨팅 / Compute | AWS Lambda | L1/L2 빠른 처리 · Fast-path processing |
| 컨테이너 / Container | AWS ECS Fargate | 샌드박스 격리 · Sandbox isolation |
| 벡터 저장소 / Vector store | PostgreSQL + pgvector | 공격 패턴 기억 · Attack memory bank |
| 인프라 / IaC | AWS CDK (Python) | 인프라 코드화 · Infrastructure as code |
| 테스트 / Testing | pytest + hypothesis | 속성 기반 테스트 · Property-based testing |
| CI/CD | GitHub Actions | 자동 빌드/배포 · Automated build & deploy |

---

## 프로젝트 구조 / Project Structure

```
sentix-aegis/
├── LICENSE                  # Apache 2.0 라이선스
├── README.md                # 이 파일 (프로젝트 안내서)
├── AGENTS.md                # 에이전트 역할 분리 가이드
├── pyproject.toml           # 의존성 + 빌드 설정
├── src/
│   └── aegis/
│       ├── common/          # 공용 타입, 설정 · Shared types & config
│       ├── genome/          # 유전자 엔진 · Genome engine
│       ├── detection/       # 탐지 파이프라인 · Detection pipeline
│       │   ├── pipeline.py  # 오케스트레이터 · Orchestrator
│       │   ├── collectors/  # L0: 클라우드 이벤트 수집 · Cloud event collectors
│       │   │   ├── aws.py       # CloudTrail, GuardDuty, SecurityHub
│       │   │   ├── azure.py     # Sentinel, Defender for Cloud
│       │   │   └── oracle.py    # Cloud Guard
│       │   └── analyzers/   # L1-L4: 분석 레이어 · Analysis layers
│       ├── immune/          # L5: AI 해킹 방어 · LLM injection defense
│       ├── metamorphic/     # 변형 엔진 · Metamorphic engine
│       └── sandbox/         # 모의 전투장 · Red vs Blue arena
│           ├── arena.py     # 전투 오케스트레이터 · Battle orchestrator
│           ├── red_agent.py # 공격 AI (6 strategies) · Attacker AI
│           ├── blue_agent.py # 방어 AI (6 strategies) · Defender AI
│           ├── battle_log.py # 전투 기록 + 분석 · Battle log & analysis
│           └── model_adapter.py # 전투 결과 -> 모델 개선 · Battle -> model improvement
├── scripts/                 # 실행 스크립트 · Runner scripts
│   ├── battle.py           # 단일 전투 · Single battle
│   ├── evolve.py           # 세대별 진화 · Generational evolution
│   └── campaign.py         # 1000전 캠페인 · 1000-battle campaign
├── tests/                   # 테스트 · Tests
├── infra/                   # AWS 인프라 스텁 · AWS CDK infrastructure (Phase 7)
├── docs/                    # 설계 문서 · Design documents
└── tasks/                   # 작업 추적 · Task tracking
```

---

## 코딩 규칙 / Coding Conventions

- **타입 힌트 필수** — 모든 함수에 타입을 적어야 해요 · Type hints on every function
- **데이터는 dataclass, 인터페이스는 Protocol** · Dataclasses for data, Protocols for interfaces
- **기본적으로 async** — `asyncio.TaskGroup` 사용 · async by default
- **유전자는 냉동** — 변형하면 항상 새 인스턴스 반환 · Genome is frozen, mutations return new instances
- **확신도는 0.0~1.0** — 퍼센트(%) 사용 금지 · Confidence as float [0.0, 1.0], never percentages
- **모든 기준값은 config에** — 코드에 숫자 직접 쓰기 금지 · All thresholds in config, no magic numbers
- **structlog으로 로깅** — JSON 형식, 모든 이벤트에 추적 ID · Structured JSON logging with correlation IDs

---

## 환경 변수 / Environment Variables

```env
AEGIS_ENV=development|staging|production
AEGIS_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR
AWS_REGION=ap-northeast-2
BEDROCK_MODEL_HAIKU=claude-haiku-4-5-20251001
BEDROCK_MODEL_SONNET=claude-sonnet-4-6
PGVECTOR_URL=postgresql://...
EVENTBRIDGE_BUS_NAME=aegis-events
```

---

## 시작하기 / Getting Started

```bash
# 프로젝트 받기 · Clone the project
git clone https://github.com/kgg1226/Sentix_Aegis.git
cd Sentix_Aegis

# 설치 (Python 3.12 이상 필요) · Install (requires Python 3.12+)
pip install -e ".[dev]"

# 테스트 실행 · Run tests
pytest

# 탐지 파이프라인 실행 (로컬 모드) · Run detection pipeline (local mode)
python -m aegis.detection.pipeline --mode local
```

## 클라우드 수집기 설정 (선택) / Cloud collector setup (optional)

수집기는 SDK가 없으면 자동으로 꺼져요 — 클라우드 없이도 로컬 모드로 동작합니다.

Collectors gracefully degrade when their SDK is not installed — AEGIS runs in local mode without any cloud dependency.

```bash
# AWS (CloudTrail, GuardDuty, SecurityHub)
pip install boto3

# Azure (Sentinel, Defender for Cloud)
pip install azure-identity azure-mgmt-securityinsight

# Oracle Cloud (Cloud Guard)
pip install oci
```

| 수집기 / Collector | 기본값 / Default | 설정 키 / Config key |
|---|---|---|
| AWS | 활성 · enabled | `aws_enabled` |
| Azure | 비활성 · disabled | `azure_enabled` + `azure_subscription_id` |
| Oracle | 비활성 · disabled | `oracle_enabled` + `oracle_compartment_id` |

---

## 현재 한계점 (v0.1) / Known Limitations

- Fitness 함수 상수가 전투 튜닝 값이에요 (5세대 진화 기반) · Fitness constants are battle-tuned (5 generations)
- L3/L4는 AWS Bedrock이 필요해요 — 로컬에서는 가짜 응답을 써요 · L3/L4 need AWS Bedrock — local mode uses mock responses
- 샌드박스가 싱글 스레드예요 · Sandbox arena is single-threaded
- AWS CDK 인프라는 스텁이에요 (Phase 7) · AWS CDK infrastructure is stubbed (Phase 7)

---

## 라이선스 / License

Apache License 2.0 — [LICENSE](./LICENSE) 참고
