# Sentix Architecture — Mermaid Diagrams

> FRAMEWORK.md의 설계를 시각화한 다이어그램.
> GitHub에서 렌더링됩니다.

---

## 5-Layer Architecture

```mermaid
graph TB
  L5["Layer 5: Self-Evolution Engine<br/><i>프롬프트/전략 자율 개선</i>"]
  L4["Layer 4: Visual Perception<br/><i>시각적 선호도 학습</i>"]
  L3["Layer 3: Pattern Engine<br/><i>행동 패턴 감지 → 선제 실행</i>"]
  L2["Layer 2: Learning Pipeline<br/><i>세션 → 메모리 → 파일 3계층 학습</i>"]
  L1["Layer 1: Governor + Agents<br/><i>중앙 통제 + 7단계 파이프라인</i>"]

  L5 --> L4 --> L3 --> L2 --> L1

  style L1 fill:#2d6a4f,color:#fff
  style L2 fill:#40916c,color:#fff
  style L3 fill:#52b788,color:#fff
  style L4 fill:#95d5b2,color:#000
  style L5 fill:#b7e4c7,color:#000
```

---

## Governor Hub-and-Spoke

```mermaid
graph TD
  Human["👤 Human<br/><i>요청 한 줄</i>"]
  Gov["🎯 Governor<br/><i>중앙 통제</i>"]

  Human --> Gov

  Gov --> P["📋 Planner<br/><i>티켓 생성</i>"]
  Gov --> D["💻 Dev<br/><i>코드 작성</i>"]
  Gov --> R["🔍 PR Review<br/><i>코드 검토</i>"]
  Gov --> O["🚀 DevOps<br/><i>배포 실행</i>"]
  Gov --> S["🛡️ Security<br/><i>보안 스캔</i>"]
  Gov --> RM["🗺️ Roadmap<br/><i>다음 계획</i>"]

  P --> Gov
  D --> Gov
  R --> Gov
  O --> Gov
  S --> Gov
  RM --> Gov

  style Gov fill:#d00000,color:#fff
  style Human fill:#003049,color:#fff
```

---

## 파이프라인 흐름

```mermaid
sequenceDiagram
  participant H as 👤 Human
  participant G as Governor
  participant P as Planner
  participant S as Security
  participant D as Dev
  participant R as PR Review
  participant O as DevOps
  participant RM as Roadmap

  H->>G: 요청
  G->>P: 티켓 생성 요청
  P-->>G: 티켓 (complexity, flags)

  opt SECURITY_FLAG
    G->>S: 선행 분석
    S-->>G: 분석 결과
  end

  G->>D: 구현 (티켓 + 분석)
  D-->>G: 코드 + 테스트

  G->>R: 리뷰 (diff + 티켓)
  alt APPROVED
    R-->>G: ✅ APPROVED
  else REJECTED
    R-->>G: ❌ REJECTED → 사유
    G->>D: 수정 요청 (사유 주입)
    D-->>G: 수정된 코드
  end

  opt DEPLOY_FLAG
    G->>O: 배포
    O-->>G: 배포 결과
  end

  G->>S: 전체 보안 스캔
  alt PASSED
    S-->>G: ✅ PASSED
  else NEEDS_FIX
    S-->>G: ❌ NEEDS_FIX
    Note over G,D: dev-fix 루프 (severity 기반 재시도)
  end

  G->>RM: 사이클 요약
  RM-->>G: 로드맵 업데이트
  G->>H: 최종 보고
```

---

## 학습 파이프라인 (3-Tier)

```mermaid
graph LR
  F["피드백 / 실행 결과"] --> T1["Tier 1: Realtime<br/><i>세션 내 휘발</i>"]
  T1 -->|"세션 종료 요약"| T2["Tier 2: Memory<br/><i>세션 간 유지</i>"]
  T2 -->|"주기적 동기화"| T3["Tier 3: Project Files<br/><i>영구 저장</i>"]

  T3 --> PL["pattern-log.jsonl"]
  T3 --> LM["lessons.md"]
  T3 --> PM["patterns.md"]
  T3 --> PR["predictions.md"]

  style T1 fill:#ffd166,color:#000
  style T2 fill:#ef476f,color:#fff
  style T3 fill:#06d6a0,color:#000
```
