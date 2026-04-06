# 에이전트별 파일 범위

> 각 에이전트가 접근할 수 있는 파일의 범위를 정의한다.
> Governor도 이 범위를 우회할 수 없다.

---

## 범위 매트릭스

| 에이전트 | 쓰기 허용 | 금지 |
|---------|----------|------|
| dev / dev-fix / dev-worker | `src/**`, `bin/**`, `scripts/**`, `__tests__/**`, `docs/**`, `app/**`, `lib/**`, `components/**` | `.github/**`, `FRAMEWORK.md`, `CLAUDE.md`, `Dockerfile`, `docker-compose.yml` |
| devops | `scripts/deploy.sh`, `Dockerfile`, `docker-compose.yml`, `entrypoint.sh` | 소스코드 수정 일체 (`src/**`, `app/**`, `lib/**`, `components/**`) |
| planner | 없음 (티켓만 생성) | 코드 파일 수정 일체 |
| pr-review | 없음 | 코드 수정. `git merge` 명령만 |
| security | 없음 | 코드 수정 일체. 읽기 전용 |
| Governor | `tasks/governor-state.json` (자신의 상태만) | 코드 직접 수정 (반드시 에이전트를 통해서) |

---

## SCOPE 위반 시 행동

```
에이전트가 SCOPE 밖 파일 수정 필요 시:
  → Governor에게 "SCOPE 확장 필요" 반환
  → Governor가 planner에게 별도 티켓 요청
  → 새 티켓으로 별도 사이클 실행
```
