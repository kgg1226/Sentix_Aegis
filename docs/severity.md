# Severity 기반 분기

> 보안 스캔, 테스트 실패 등의 이슈를 severity에 따라 분류하고,
> 각 severity에 맞는 재시도/에스컬레이션 로직을 적용한다.

---

## 분류 기준

| Severity | 행동 | 재시도 | 실패 시 |
|----------|------|--------|---------|
| critical | dev-fix 즉시 실행 | 최대 3회 | roadmap 에스컬레이션 + 인간 알림 |
| warning | dev-fix 실행 | 최대 10회 | roadmap 에스컬레이션 |
| suggestion | 로깅만 | 없음 | dev-fix 미실행 |

---

## 자동 승격

```
동일 패턴 3회 반복 → 구조적 개선 항목으로 자동 승격
  suggestion → warning
  warning → critical
```

## CI 워크플로우 매핑

```
security-scan.yml:
  CRITICAL (npm audit critical / Trivy critical / secrets detected) → FAILED → dev-fix (3회)
  MEDIUM   (npm audit high / Trivy high / auth gap)                → NEEDS_FIX → dev-fix (10회)
  LOW      (no findings)                                           → PASSED → roadmap
```
