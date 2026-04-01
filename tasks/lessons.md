# Lessons learned

## 2026-03-25 — Project bootstrap
- Fitness function v1 had 12 critical defects (AEGIS-F001 through F012). All magic numbers need empirical calibration, not hand-tuning.
- Naive gyroscope (balance restoration) is harmful during intentional asymmetry (wartime). Adaptive homeostasis with moving target is the correct approach.
- Detection confidence → action mapping is a POLICY problem, not an algorithm problem. Never auto-block below 0.90 confidence.

## 2026-04-01 — 보안 분석 자동화 워크플로우에서 배운 점 (외부 사례 분석)

### 핵심 교훈

1. **도메인 지식 없이도 구조화된 파이프라인으로 결과를 낼 수 있다**
   - AI에게 "탐지와 대응"을 기대하면 실망할 확률이 높다. 하지만 분석과 분류(조사/보고서)에 특화시키면 놀라운 결과가 나온다.
   - AEGIS에 적용: 현재 detection pipeline(L0-L5)은 잘 구축되어 있지만, **분석 결과를 구조화된 조사 보고서로 자동 생성하는 기능**이 부족하다.

2. **실전 분석 워크플로우를 파이프라인으로 구현해야 한다**
   - 실전 워크플로우: 케이스 분석 → GTI 공격기법 분석 → TTP 매핑 → 룰 존재 여부 확인 → 미비 룰 생성 → 탐지 검증 → 레트로 헌트 → 추가 분석 반복 → 보고서 작성
   - AEGIS에 적용: 현재 Red/Blue arena는 시뮬레이션 중심이다. 실제 클라우드 이벤트에 대한 **조사(Investigation) 파이프라인**이 필요하다:
     - CloudEvent 수신 → L0-L5 탐지 → TTP 매핑(MITRE ATT&CK) → 기존 룰 매칭 → 신규 룰 자동 생성 → 검증 → 레트로 헌트(과거 이벤트 재검사) → 조사 보고서 자동 생성

3. **MCP 통합이 핵심 자동화 수단이다**
   - 원 저자는 MCP(Model Context Protocol)를 이미 만들어서 사용 중이며, skills도 MCP 안에 포함시켰다.
   - AEGIS에 적용: Phase 7에서 Bedrock 통합 시, **MCP 서버로 AEGIS를 노출**하면 분석가가 Claude Code에서 직접 조사 워크플로우를 실행할 수 있다.

4. **보고서 생성은 가장 높은 ROI를 가진 기능이다**
   - 원 저자는 1시간 만에 전체 조사 보고서를 완성(30분은 다듬기). 사람이 수동으로 하면 하루 이상 걸리는 작업.
   - AEGIS에 적용: campaign/battle 리포트는 있지만, **실제 보안 사고 조사 보고서 형태의 출력**이 없다. 다음을 포함해야 한다:
     - 사고 요약 (Executive Summary)
     - 공격 타임라인 (Attack Timeline)
     - TTP 매핑 테이블 (MITRE ATT&CK)
     - 탐지 룰 분석 (기존 탐지 여부 + 신규 룰 제안)
     - 영향 범위 분석 (Impact Assessment)
     - 권고 사항 (Recommendations)

5. **반복적 분석 루프가 품질을 결정한다**
   - "몇 번의 반복" — 한 번의 분석으로 끝나지 않는다. 레트로 헌트 결과로 추가 분석하고, 그 결과로 다시 룰을 개선하는 피드백 루프.
   - AEGIS에 적용: 현재 campaign의 mid-campaign adaptation이 이 개념과 유사하다. 이를 실제 탐지 파이프라인에도 적용하여 **탐지 → 분석 → 룰 개선 → 재검증의 자동 피드백 루프**를 구축해야 한다.

### 구현 우선순위 제안

| 우선순위 | 기능 | 현재 상태 | 필요한 작업 |
|---------|------|----------|-----------|
| 1 | 조사 보고서 자동 생성 | campaign 리포트만 존재 | Investigation Report Generator 구현 |
| 2 | TTP 자동 매핑 | Red agent에 MITRE 기법 있음 | 탐지 이벤트 → ATT&CK TTP 자동 매핑 |
| 3 | 레트로 헌트 엔진 | 없음 | 과거 이벤트 재검사 엔진 구현 |
| 4 | 탐지 룰 자동 생성/검증 | L1 pattern matcher만 존재 | 동적 룰 생성 + 검증 파이프라인 |
| 5 | MCP 서버 인터페이스 | 없음 | AEGIS를 MCP 서버로 노출 |
