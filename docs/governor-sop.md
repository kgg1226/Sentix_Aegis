# Governor SOP — 7단계 파이프라인 상세

> CLAUDE.md의 SOP 요약에서 참조되는 상세 문서.

---

## 전체 흐름

```
Step 0: CLAUDE.md + FRAMEWORK.md 읽기 + 세션 복구 확인
Step 1: 요청 수신
Step 2: lessons.md + patterns.md 로드 (과거 실패/패턴 학습)
Step 3: 실행 계획 수립 (어떤 에이전트를, 어떤 순서로, 어떤 컨텍스트와 함께)
Step 4: 에이전트 순차/병렬 소환 → 결과 수거 → 판단 → 다음 결정
Step 5: 이슈 시 교차 판단 (재시도 / 에스컬레이션 / planner 재소환)
Step 6: 전체 완료 → 인간에게 최종 보고
Step 7: pattern-engine 실행 → 이번 사이클 학습 → governor-state.json 업데이트
```

---

## Step 0: 세션 복구 확인

모든 파이프라인 실행 전에 먼저 확인:

```
1. tasks/governor-state.json 읽기
2. status가 'in_progress'이면 → 중단된 파이프라인이 존재
3. plan[]에서 마지막으로 완료된 phase를 찾는다
4. 해당 phase 다음부터 파이프라인을 재개한다
5. 이미 완료된 에이전트 결과는 재사용 (재실행 안 함)
```

CLI 모드: `sentix resume` 실행
대화 모드: [SENTIX:RESUME] 태그로 재개 상태 안내

복구 불가 상태:
- governor-state.json이 손상된 경우 → `sentix run`으로 새 사이클 시작
- 코드 상태가 불일치하는 경우 → git stash 후 재시작 권장

---

## 실행 계획 예시

```
요청: "인증에 세션 만료 추가해줘"

Governor 판단:
  1. planner 소환 — 요청 + lessons.md + patterns.md 주입
     → 결과: 티켓 (COMPLEXITY: medium, DEPLOY_FLAG: true, SECURITY_FLAG: true)

  2. SECURITY_FLAG → security 선행 분석 → "현재 auth 구조 분석"

  3. dev 소환 — 티켓 + security 분석 결과 주입
     → 결과: 코드 변경 + 테스트 + pre-fix snapshot

  4. pr-review 소환 — 티켓 + dev 결과 + pre-fix snapshot 주입
     → APPROVED → 머지
     → REJECTED → dev에게 사유 전달 + 재실행

  5. DEPLOY_FLAG: true → devops 실행 (env-profiles 참조)

  6. security 소환 (전체 스캔)
     → PASSED → roadmap 소환
     → NEEDS_FIX → dev-fix → pr-review → devops → security (루프)

  7. pattern-engine 실행 → 사이클 기록 → 완료 보고
```

---

## 실행 게이트 (Pre-execution)

파이프라인 시작 전에 다음 게이트를 확인한다:

```
[sentix run 실행]
  ↓
[Pre-Gate 1] 활성 티켓 존재 확인 (hotfix 모드면 건너뜀)
[Pre-Gate 2] Pre-fix test snapshot 존재 확인
  ↓
  경고만 출력 (hard block 아님) → 파이프라인 계속
  ↓
[Claude Code 실행]
```

---

## 검증 게이트 (Step 4 → 5 사이)

에이전트 작업 완료 후, **결정론적 코드**가 하드 룰 위반 여부를 자동 검증한다.
이것은 AI의 판단이 아니라 git diff 분석 기반의 코드 검증이다.

```
[에이전트 작업 완료]
  ↓
[검증 게이트 실행] ← src/lib/verify-gates.js (코드가 판단)
  ✓ SCOPE 준수 — 변경 파일이 허용 범위 안에 있는가
  ✓ export 삭제 없음 — 기존 API가 삭제되지 않았는가
  ✓ 테스트 삭제 없음 — 기존 테스트가 삭제/약화되지 않았는가
  ✓ 순삭제 50줄 이내 — 대량 삭제가 없는가
  ↓
  PASS → 다음 단계 진행
  FAIL → 경고 기록 + violations 상세 출력
```

---

## 에이전트별 자기 검증 (Self-Verification)

각 에이전트는 결과를 Governor에게 반환하기 전에 반드시 자기 검증을 수행한다.

### dev / dev-fix

```
작업 완료 전 반드시 확인:
  □ npm test 실행 → 모든 테스트 통과
  □ 변경 파일이 티켓 SCOPE 안에 있는가
  □ 기존 export를 삭제하지 않았는가
  □ 기존 테스트를 삭제/약화하지 않았는가
  □ 순삭제가 50줄을 넘지 않는가
  → 위반 발견 시: 스스로 수정 후 다시 확인
```

### pr-review

```
리뷰 시 반드시 확인:
  □ 하드 룰 6개 위반 없는가
  □ dev가 자기 검증을 수행했는가 (테스트 통과 기록 확인)
  □ SCOPE 밖 파일 변경이 없는가
  → REJECTED 시 구체적인 사유를 dev에게 전달
```

### security

```
스캔 후 반드시 확인:
  □ false positive 필터링 완료
  □ 발견된 이슈의 severity 분류가 정확한가
  □ 이전 security-report.md와 비교하여 regression 없는가
```

---

## 핫픽스 파이프라인 (Hotfix SOP)

긴급 수정이 필요할 때 전체 7단계 파이프라인은 비효율적이다.
핫픽스 모드는 다음 키워드에서 자동 활성화된다:

```
감지 키워드: 핫픽스, hotfix, 긴급, urgent, typo, 오타,
            one-liner, 한 줄 수정, quick fix, 간단 수정
```

실행 흐름:
```
Step 1: 요청 수신 + 모드 판단 (hotfix 감지)
Step 2: lessons.md 로드 (과거 실패 패턴 확인)
Step 3: Governor가 직접 코드 수정 (에이전트 소환 없음)
Step 7: pattern-log 기록 + lessons.md 업데이트
```

제한사항:
- 하드 룰 6개 전부 적용
- SCOPE 제한 동일 적용
- 검증 게이트 동일 실행
- 순삭제 50줄 초과 시 표준 파이프라인으로 전환 권장

---

## 에이전트 소환 규칙

- 각 에이전트는 Governor를 통해서만 소환됨 (에이전트 간 직접 통신 없음)
- 이전 에이전트의 결과가 다음 에이전트의 컨텍스트로 주입됨
- 에이전트가 실패하면 Governor가 재시도/에스컬레이션 판단
- SECURITY_FLAG, DEPLOY_FLAG 등 티켓 플래그에 따라 단계 건너뛰기 가능
