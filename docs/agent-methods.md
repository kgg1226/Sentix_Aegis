# Agent Methods — 에이전트별 메서드 명세

> FRAMEWORK.md의 에이전트 정의를 보완하는 메서드 수준 상세 명세.
> 각 에이전트가 **어떤 단계를 어떤 순서로 수행하는지** 정의한다.
> 아키텍처 원칙: [Anthropic Building Effective Agents](https://www.anthropic.com/engineering/building-effective-agents) 기반.

---

## 설계 원칙

### 1. Generator-Evaluator 분리

```
생성자 (dev/dev-fix)와 평가자 (pr-review)는 완전히 분리된다.
생성자는 품질 판단을 하지 않는다. 하드룰 자기 검증만 수행한다.
평가자는 코드를 수정하지 않는다. 판정만 내린다.
```

### 2. 산출물 제약, 경로 자유 (Constrain Outputs, Free Paths)

```
planner는 WHAT(무엇을)과 WHERE(어디를)만 정의한다.
HOW(어떻게)는 dev가 결정한다.
planner가 구현 방법을 명세하면 틀릴 경우 하류에 cascade된다.
```

### 3. 회의적 평가자 (Skeptical Evaluator)

```
pr-review는 의도적으로 회의적으로 튜닝된다.
에이전트는 자기 작업에 관대하다 — 별도 평가자를 엄격하게 만드는 것이 효과적이다.
의심스러우면 REJECTED. 관대함보다 엄격함이 낫다.
```

### 4. 복잡도 기반 강도 조절 (Conditional Intensity)

```
평가자의 가치는 태스크가 모델의 단독 능력 경계를 넘을 때 가장 높다.
low complexity  → 하드룰 체크만 (빠른 통과)
mid complexity  → 하드룰 + 품질 기준 채점
high complexity → 하드룰 + 품질 기준 + 실제 동작 검증
```

### 5. Sprint Contract (사전 합의)

```
구현 전에 생성자와 평가자가 "완료 조건"을 합의한다.
planner가 티켓을 만들면 pr-review가 평가 가능성을 사전 검증한다.
불명확한 기준은 구현 전에 교정된다 — 사후 논쟁을 방지한다.
```

### 6. 하네스 간소화 원칙

```
파이프라인의 모든 단계는 "모델이 혼자 못 하는 것"에 대한 가정이다.
그 가정은 주기적으로 스트레스 테스트해야 한다.
모델 능력이 충분해지면 단계를 생략할 수 있다.

config.toml [harness] 섹션으로 제어:
  skip_contract = false       # contract 단계 생략 여부
  skip_review_on_low = true   # low complexity 리뷰 생략
  evaluator_intensity = "auto" # auto: complexity에 따라 자동 조절
```

---

## planner

요청을 분석하고 실행 가능한 티켓으로 변환한다.
**WHAT과 WHERE만 정의한다. HOW는 정의하지 않는다.**

### Methods

```
planner.analyze()
  → 요청 분류 (BUG / FEATURE / VERSION / GENERAL)
  → 키워드 추출
  → 유형별 파이프라인 결정

planner.research()
  → tasks/lessons.md 검색 — 동일/유사 패턴의 과거 실패
  → tasks/patterns.md 검색 — 관련 사용자 행동 패턴
  → 기존 티켓 검색 — 중복 방지

planner.scope()
  → 변경 범위 결정 (영향받는 파일/모듈 식별)
  → SCOPE 정의: 어떤 파일이 변경 대상인가
  → ACCEPTANCE 정의: 완료 조건은 무엇인가
  ██ 금지: 구체적 구현 방법 명세 (함수명, 알고리즘, 라이브러리 선택 등) ██

planner.estimate()
  → COMPLEXITY 판정 (low / mid / high)
  → 플래그 설정: DEPLOY_FLAG, SECURITY_FLAG, PARALLEL_HINT
  → high → dev-swarm 권고 여부

planner.emit()
  → 티켓 생성 (tasks/tickets/)
  → 티켓 필드: TICKET_ID, TITLE, SCOPE, ACCEPTANCE, COMPLEXITY, FLAGS
  → tasks/tickets/index.json 업데이트
```

### 출력 스키마

```
TICKET_ID:      dev-044
TITLE:          세션 만료 검증 추가
TYPE:           feature
SCOPE:          src/auth/**, __tests__/auth/**
ACCEPTANCE:
  - 세션 만료 시 401 반환
  - 만료 시간 설정 가능
  - 기존 인증 흐름 유지
COMPLEXITY:     mid
DEPLOY_FLAG:    true
SECURITY_FLAG:  true
PARALLEL_HINT:  null
```

### planner가 정의하면 안 되는 것

```
✗ "jwt.verify()를 사용하라"          → 구현 방법은 dev가 결정
✗ "middleware를 express.use()로 등록" → 기술 디테일은 dev가 결정
✗ "Redis에 세션을 저장하라"           → 저장 방식은 dev가 결정
✗ "함수명은 checkExpiry로 하라"       → 네이밍은 dev가 결정
```

---

## pr-review — Contract 단계 (dev 전)

dev가 구현을 시작하기 전에, 티켓의 평가 가능성을 사전 검증한다.

### Methods

```
pr-review.contract()
  → 티켓의 ACCEPTANCE 기준 검토
  → 각 기준이 검증 가능한가? (코드 리뷰로 판단할 수 있는가?)
  → 각 기준이 명확한가? (해석의 여지가 없는가?)
  → 불명확한 기준 발견 시:
      → planner에게 피드백 반환
      → 피드백 내용: 어떤 기준이, 왜 불명확한지, 어떻게 교정하면 되는지
      → planner 재조정 후 다시 contract() 실행
  → 모든 기준이 명확하면: CONTRACT_APPROVED 반환
```

### Contract 판단 기준

```
검증 가능 (PASS):
  "세션 만료 시 401 반환"          → 테스트로 검증 가능
  "기존 인증 흐름 유지"            → 기존 테스트 통과로 검증 가능
  "만료 시간 설정 가능"            → 설정 파라미터 존재 여부로 검증 가능

검증 불가 (FEEDBACK):
  "코드가 깔끔해야 한다"           → 주관적, 기준 불명확
  "성능이 좋아야 한다"             → 수치 기준 없음
  "보안이 강화되어야 한다"          → 구체적 조건 없음
```

---

## dev

티켓의 ACCEPTANCE 조건을 충족하는 코드를 구현한다.
**구현 방법은 dev가 자율적으로 결정한다.**

### Methods

```
dev.snapshot()
  → npm test 실행 → tasks/.pre-fix-test-results.json 저장
  → 현재 테스트 상태 기록 (회귀 검증 기준선)

dev.implement()
  → SCOPE 내 파일만 수정
  → ACCEPTANCE 조건 충족을 목표로 구현
  → 구현 방법은 dev가 결정 (planner의 HOW 명세 없음)

dev.test()
  → 새 코드에 대한 테스트 작성
  → npm test 실행
  → 기존 테스트 + 새 테스트 모두 통과 확인

dev.verify()
  → 하드룰 자기 검증만 수행:
    □ 변경 파일이 SCOPE 안에 있는가
    □ 기존 export를 삭제하지 않았는가
    □ 기존 테스트를 삭제/약화하지 않았는가
    □ 순삭제가 50줄을 넘지 않는가
    □ 기존 기능/핸들러를 삭제하지 않았는가
  → 위반 발견 시: 스스로 수정 후 다시 verify()
  ██ 품질 판단은 하지 않는다 — pr-review에 위임 ██

dev.report()
  → diff 요약 반환
  → 테스트 결과 반환
  → 변경 파일 목록 반환
```

---

## pr-review — 평가 단계 (dev 후)

dev의 결과물을 티켓 기준으로 평가한다.
**의도적으로 회의적(skeptical)으로 판단한다.**

### Methods

```
pr-review.diff()
  → 전체 변경 내용 확인 (git diff)
  → 변경 범위가 SCOPE 내인지 확인
  → pre-fix snapshot과 비교하여 회귀 여부 파악

pr-review.validate()
  → 하드룰 검증 (결정론적 — verify-gates.js와 동일 기준)
    □ SCOPE 준수
    □ export 삭제 없음
    □ 테스트 삭제 없음
    □ 순삭제 50줄 이내
    □ 기능/핸들러 삭제 없음
  → 하나라도 위반 시: 즉시 REJECTED (grade() 진행 안 함)

pr-review.grade()
  → COMPLEXITY=low이면 생략 (하드룰 통과만으로 APPROVED)
  → COMPLEXITY=mid/high이면 4가지 품질 기준 채점:

    1. 정확성 (Correctness)
       → 티켓의 ACCEPTANCE 조건을 모두 충족하는가?
       → 엣지 케이스를 처리했는가?

    2. 일관성 (Consistency)
       → 기존 코드베이스의 패턴/컨벤션을 따르는가?
       → 네이밍, 구조, 에러 처리 방식이 기존과 일치하는가?

    3. 간결성 (Simplicity)
       → 불필요한 추상화, 과도한 설계가 없는가?
       → 가장 단순한 해결책인가?

    4. 테스트 충실도 (Test Coverage)
       → 새 코드에 대한 테스트가 있는가?
       → 엣지 케이스를 테스트하는가, 표면적 테스트인가?

  → 각 기준별 PASS / FAIL
  → 하나라도 FAIL이면 REJECTED

pr-review.calibrate()
  → tasks/lessons.md에서 과거 놓친 이슈를 few-shot 예시로 참조
  → "이전에 이런 패턴을 놓쳤다. 이번에도 확인하라"
  → 자기 합리화 방지: "이슈를 발견했다면 절대 스스로 합리화하지 마라"

pr-review.verdict()
  → 최종 판정: APPROVED / REJECTED
  → REJECTED 시: 구체적 사유 + 어떤 기준이 미달인지 명시
  → APPROVED 시: NEEDS_DEPLOY 여부 판단
```

### 채점 기준 상세

```
┌──────────────┬─────────────────────────────────┬───────────────────────┐
│ 기준         │ PASS 조건                        │ FAIL 예시             │
├──────────────┼─────────────────────────────────┼───────────────────────┤
│ 정확성       │ ACCEPTANCE 조건 100% 충족         │ 조건 하나 누락         │
│ 일관성       │ 기존 패턴과 일치                   │ 새로운 컨벤션 도입      │
│ 간결성       │ 불필요한 추상화 없음               │ 과도한 설계, 미사용 코드 │
│ 테스트 충실도 │ 엣지 케이스 포함한 테스트           │ happy path만 테스트    │
└──────────────┴─────────────────────────────────┴───────────────────────┘
```

### 복잡도별 리뷰 강도

```
COMPLEXITY=low:
  validate() → verdict()
  grade() 생략 — 하드룰 통과만으로 충분

COMPLEXITY=mid:
  validate() → grade() → calibrate() → verdict()
  4가지 품질 기준 전체 채점

COMPLEXITY=high:
  validate() → grade() → calibrate() → verdict()
  4가지 품질 기준 + 실제 동작 검증 (Playwright 등 해당 시)
```

---

## dev-fix

pr-review 또는 security가 발견한 이슈를 수정한다.
**LESSON_LEARNED 기록이 필수다.**

### Methods

```
dev-fix.diagnose()
  → 이슈 원인 분석
  → pr-review의 REJECTED 사유 또는 security findings 참조
  → Governor 교차 판단이 있으면 함께 참조
  → 원인이 SCOPE 밖에 있으면 Governor에게 "SCOPE 확장 필요" 반환

dev-fix.fix()
  → SCOPE 내 코드 수정
  → 이슈와 무관한 파일은 절대 수정하지 않음

dev-fix.test()
  → npm test 실행
  → pre-fix snapshot 대비 회귀 없음 확인
  → 수정한 이슈에 대한 테스트 추가/보강

dev-fix.learn()
  → LESSON_LEARNED 작성 (필수 — 생략 불가)
  → tasks/lessons.md에 추가
  → 형식: 날짜 + 이슈 요약 + 근본 원인 + 교훈
  → 동일 패턴 3회 반복 감지 시 severity 자동 승격

dev-fix.report()
  → 수정 diff 반환
  → 테스트 결과 반환
  → LESSON_LEARNED 내용 반환
```

---

## security

전체 코드베이스를 읽기 전용으로 스캔한다.

### Methods

```
security.scan()
  → 전체 코드베이스 보안 분석
  → 이전 tasks/security-report.md와 비교 (regression 확인)

security.classify()
  → 발견 항목별 severity 분류 (critical / warning / suggestion)
  → false positive 필터링

security.report()
  → tasks/security-report.md 생성/업데이트
  → VERDICT: PASSED / NEEDS_FIX
  → NEEDS_FIX 시: 각 finding의 severity + 위치 + 설명
```

---

## roadmap

사이클 전체 이력을 분석하여 다음 계획을 수립한다.

### Methods

```
roadmap.analyze()
  → 이번 사이클의 요청, 티켓, 결과, 이슈, 리포트 종합 분석
  → tasks/lessons.md에서 반복 패턴 식별
  → tasks/patterns.md에서 트렌드 파악

roadmap.plan()
  → 즉시 / 단기 / 장기 계획 수립
  → 다음 티켓 초안 작성

roadmap.emit()
  → tasks/roadmap.md 생성/업데이트
```

---

## 전체 파이프라인 흐름 (Methods 기반)

```
사용자 요청
  │
  ▼
planner.analyze() → research() → scope() → estimate() → emit()
  │                                                        │
  │  티켓 생성                                               │
  ▼                                                        │
pr-review.contract()  ◄─────────────────────────────────────┘
  │
  │  CONTRACT_APPROVED?
  │  ├─ NO  → planner에게 피드백 → planner.scope() 재실행
  │  └─ YES → 다음 단계
  ▼
dev.snapshot() → implement() → test() → verify() → report()
  │
  │  [검증 게이트: verify-gates.js]
  ▼
pr-review.diff() → validate() → grade()* → calibrate() → verdict()
  │                               (* low면 생략)
  │  APPROVED?
  │  ├─ NO  → dev-fix.diagnose() → fix() → test() → learn() → report()
  │  │        → pr-review 재실행
  │  └─ YES → 다음 단계
  ▼
[DEPLOY_FLAG?] → devops
  │
  ▼
[SECURITY_FLAG?] → security.scan() → classify() → report()
  │                  │
  │                  │  NEEDS_FIX? → dev-fix → pr-review → (반복)
  ▼
roadmap.analyze() → plan() → emit()
  │
  ▼
[완료: 버전 범프 + lessons 업데이트 + 최종 보고]
```

---

## config.toml 하네스 설정

```toml
[harness]
# 주기적으로 재검토: 모델 능력 향상 시 단계 생략 가능
skip_contract = false        # true: contract 단계 생략 (planner 신뢰도 높을 때)
skip_review_on_low = true    # true: low complexity는 하드룰만 체크
evaluator_intensity = "auto" # "auto" | "full" | "minimal"
                             # auto: complexity에 따라 자동 조절
                             # full: 항상 전체 채점
                             # minimal: 항상 하드룰만
```

---

## 참조

- FRAMEWORK.md — 에이전트 정의, 5-Layer 아키텍처
- docs/governor-sop.md — 7단계 파이프라인 상세
- docs/agent-scopes.md — 에이전트별 파일 접근 범위
- docs/severity.md — severity 분류 + 재시도 로직
- src/lib/verify-gates.js — 하드룰 결정론적 검증 코드
