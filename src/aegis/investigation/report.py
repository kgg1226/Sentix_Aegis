"""Investigation Report Generator — 보안 사고 조사 보고서 자동 생성.

포스트에서 배운 핵심: 보고서 생성이 가장 높은 ROI를 가진 기능.
사람이 하루 걸리는 작업을 1시간 내로 완성.

보고서 구성:
  1. Executive Summary (사고 요약)
  2. Attack Timeline (공격 타임라인)
  3. TTP Mapping Table (MITRE ATT&CK 매핑)
  4. Detection Rule Analysis (기존 탐지 + 신규 룰 제안)
  5. Retro Hunt Findings (레트로 헌트 결과)
  6. Impact Assessment (영향 범위)
  7. Recommendations (권고 사항)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aegis.investigation.ttp_mapper import TTPMapping, TTPMatch, MitreTactic
from aegis.investigation.retro_hunt import DetectionRule, RetroHuntResult
from aegis.investigation.rule_generator import GapAnalysis, CorrelationRule, PREDEFINED_CORRELATION_RULES


# ---------------------------------------------------------------------------
# Report Data Model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class InvestigationReport:
    """보안 사고 조사 보고서."""

    case_id: str
    title: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    analyst: str = "AEGIS Automated Investigation"

    # 입력 데이터
    events: list[dict] = field(default_factory=list)
    ttp_mapping: TTPMapping | None = None
    gap_analysis: GapAnalysis | None = None
    generated_rules: list[DetectionRule] = field(default_factory=list)
    retro_results: list[RetroHuntResult] = field(default_factory=list)

    # 메타데이터
    severity: str = "MEDIUM"   # LOW / MEDIUM / HIGH / CRITICAL
    status: str = "OPEN"       # OPEN / IN_PROGRESS / CLOSED
    correlation_matches: list[CorrelationRule] = field(default_factory=list)

    def render_markdown(self) -> str:
        """보고서를 마크다운 형식으로 렌더링 (10-section)."""
        sections = [
            self._render_header(),
            self._render_executive_summary(),
            self._render_actor_profiles(),
            self._render_timeline(),
            self._render_evidence_chain(),
            self._render_ttp_table(),
            self._render_rule_analysis(),
            self._render_retro_findings(),
            self._render_impact(),
            self._render_recommendations(),
        ]
        return "\n\n".join(sections)

    # --- Section Renderers ---

    def _render_header(self) -> str:
        return f"""# Investigation Report: {self.title}

| Field | Value |
|-------|-------|
| Case ID | `{self.case_id}` |
| Severity | **{self.severity}** |
| Status | {self.status} |
| Created | {self.created_at} |
| Analyst | {self.analyst} |
| Total Events | {len(self.events)} |"""

    def _render_executive_summary(self) -> str:
        lines = ["## 1. Executive Summary", ""]

        if not self.ttp_mapping or not self.ttp_mapping.matches:
            lines.append("분석 대상 이벤트에서 특이사항이 발견되지 않았습니다.")
            return "\n".join(lines)

        tactics = self.ttp_mapping.tactics_involved
        tactic_names = [t.name.replace("_", " ").title() for t in tactics]
        coverage = self.ttp_mapping.kill_chain_coverage
        max_sev = self.ttp_mapping.max_severity

        lines.append(
            f"총 **{len(self.events)}**건의 이벤트를 분석한 결과, "
            f"**{len(self.ttp_mapping.matches)}**건의 TTP 매칭이 식별되었습니다."
        )
        lines.append("")
        lines.append(f"- **관련 전술**: {', '.join(tactic_names)}")
        lines.append(f"- **킬 체인 커버리지**: {coverage:.0%} ({len(tactics)}/14 전술)")
        lines.append(f"- **최대 위험도**: {max_sev:.2f}")

        if coverage >= 0.5:
            lines.append("")
            lines.append(
                "> **경고**: 킬 체인 커버리지가 50%를 초과합니다. "
                "이는 조직적이고 계획된 공격 캠페인을 시사합니다."
            )

        if self.gap_analysis and self.gap_analysis.gap_count > 0:
            lines.append("")
            lines.append(
                f"- **탐지 룰 갭**: {self.gap_analysis.gap_count}개 기법에 대한 "
                f"탐지 룰이 누락됨 (커버리지: {self.gap_analysis.coverage_rate:.0%})"
            )

        if self.correlation_matches:
            lines.append("")
            lines.append(
                f"- **상관 분석**: {len(self.correlation_matches)}개의 "
                f"다단계 공격 패턴이 감지됨"
            )
            for cr in self.correlation_matches:
                lines.append(f"  - `{cr.rule_id}` {cr.name} (severity: {cr.severity:.2f})")

        return "\n".join(lines)

    def _render_actor_profiles(self) -> str:
        lines = ["## 2. Actor Profiles", ""]

        if not self.events:
            lines.append("행위자 정보가 없습니다.")
            return "\n".join(lines)

        from aegis.investigation.bridge import build_actor_profiles
        profiles = build_actor_profiles(self.events)
        if not profiles:
            lines.append("행위자 정보가 없습니다.")
            return "\n".join(lines)

        # risk score 내림차순 정렬
        sorted_profiles = sorted(profiles.values(), key=lambda p: p.risk_score, reverse=True)

        lines.append("| Identity | Risk | Events | IPs | Regions | Max Severity | Activity Window |")
        lines.append("|----------|------|--------|-----|---------|-------------|-----------------|")

        for p in sorted_profiles[:20]:
            identity = p.identity
            if len(identity) > 50:
                identity = identity[:47] + "..."
            risk_label = "🔴" if p.risk_score >= 0.7 else "🟡" if p.risk_score >= 0.4 else "🟢"

            window = ""
            if p.first_seen and p.last_seen:
                window = f"{p.first_seen[:16]}~{p.last_seen[11:16]}"

            lines.append(
                f"| {identity} | {risk_label} {p.risk_score:.2f} | "
                f"{p.event_count} | {p.unique_ips} | "
                f"{len(p.regions)} | {p.max_severity:.2f} | {window} |"
            )

        # 고위험 행위자 경고
        high_risk = [p for p in sorted_profiles if p.risk_score >= 0.7]
        if high_risk:
            lines.append("")
            lines.append(f"> **{len(high_risk)}명의 고위험 행위자**가 식별되었습니다.")
            for p in high_risk:
                reasons = []
                if p.unique_ips > 3:
                    reasons.append(f"{p.unique_ips}개 IP 사용")
                if p.is_multi_region:
                    reasons.append(f"{len(p.regions)}개 리전 접근")
                if p.max_severity >= 0.8:
                    reasons.append(f"고위험 행동 (severity {p.max_severity:.2f})")
                lines.append(f"> - `{p.identity[:50]}`: {', '.join(reasons)}")

        return "\n".join(lines)

    def _render_evidence_chain(self) -> str:
        lines = ["## 4. Evidence Chain (Attack Flow)", ""]

        if not self.ttp_mapping or not self.ttp_mapping.matches:
            lines.append("증거 체인을 구성할 수 없습니다.")
            return "\n".join(lines)

        by_tactic = self.ttp_mapping.techniques_by_tactic()

        # 전술 순서대로 공격 흐름 시각화
        tactic_order = [
            MitreTactic.RECONNAISSANCE,
            MitreTactic.INITIAL_ACCESS,
            MitreTactic.EXECUTION,
            MitreTactic.PERSISTENCE,
            MitreTactic.PRIVILEGE_ESCALATION,
            MitreTactic.DEFENSE_EVASION,
            MitreTactic.CREDENTIAL_ACCESS,
            MitreTactic.DISCOVERY,
            MitreTactic.LATERAL_MOVEMENT,
            MitreTactic.COLLECTION,
            MitreTactic.COMMAND_AND_CONTROL,
            MitreTactic.EXFILTRATION,
            MitreTactic.IMPACT,
        ]

        active_tactics = [t for t in tactic_order if t in by_tactic]

        if len(active_tactics) < 2:
            lines.append("단일 전술만 감지되어 공격 체인이 구성되지 않습니다.")
            if active_tactics:
                t = active_tactics[0]
                matches = by_tactic[t]
                tech_names = list({m.technique.name for m in matches})
                lines.append(f"- {t.name}: {', '.join(tech_names)}")
            return "\n".join(lines)

        # 공격 흐름 다이어그램 (텍스트)
        lines.append("```")
        flow_parts = []
        for t in active_tactics:
            matches = by_tactic[t]
            tech_names = list({m.technique.name for m in matches})
            short_name = t.name.replace("_", " ").title()
            techs_str = ", ".join(tech_names[:2])
            if len(tech_names) > 2:
                techs_str += f" +{len(tech_names)-2}"
            flow_parts.append(f"[{short_name}]\n  {techs_str}")

        lines.append("\n    |\n    v\n".join(flow_parts))
        lines.append("```")

        # 상관 분석 룰 매칭
        if self.ttp_mapping:
            technique_map: dict[str, str] = {}
            for m in self.ttp_mapping.matches:
                technique_map[m.event_id] = m.technique.technique_id

            matched_correlations: list[CorrelationRule] = []
            for cr in PREDEFINED_CORRELATION_RULES:
                if cr.matches_sequence(self.events, technique_map):
                    matched_correlations.append(cr)

            self.correlation_matches = matched_correlations

            if matched_correlations:
                lines.append("")
                lines.append("### Correlation Rule Matches")
                lines.append("")
                for cr in matched_correlations:
                    seq = " → ".join(cr.technique_sequence)
                    lines.append(f"- **{cr.name}** (`{cr.rule_id}`, severity: {cr.severity:.2f})")
                    lines.append(f"  - 패턴: `{seq}` (within {cr.time_window_hours}h)")
                    lines.append(f"  - 설명: {cr.description}")

        return "\n".join(lines)

    def _render_timeline(self) -> str:
        lines = ["## 3. Attack Timeline", ""]

        if not self.events:
            lines.append("이벤트가 없습니다.")
            return "\n".join(lines)

        # 이벤트를 타임스탬프 순으로 정렬
        sorted_events = sorted(
            self.events,
            key=lambda e: e.get("timestamp", ""),
        )

        lines.append("| Time | Action | Identity | Source IP | Severity |")
        lines.append("|------|--------|----------|-----------|----------|")

        for evt in sorted_events[:50]:  # 최대 50건
            ts = evt.get("timestamp", "N/A")
            if len(ts) > 19:
                ts = ts[:19]  # truncate microseconds
            action = evt.get("action", "N/A")
            identity = evt.get("identity", "N/A")
            if len(identity) > 40:
                identity = identity[:37] + "..."
            src_ip = evt.get("source_ip", "N/A")
            severity = evt.get("severity", "N/A")
            if isinstance(severity, float):
                severity = f"{severity:.2f}"

            lines.append(f"| {ts} | `{action}` | {identity} | {src_ip} | {severity} |")

        if len(sorted_events) > 50:
            lines.append(f"\n*... 외 {len(sorted_events) - 50}건 생략*")

        return "\n".join(lines)

    def _render_ttp_table(self) -> str:
        lines = ["## 5. MITRE ATT&CK TTP Mapping", ""]

        if not self.ttp_mapping or not self.ttp_mapping.matches:
            lines.append("TTP 매칭이 없습니다.")
            return "\n".join(lines)

        by_tactic = self.ttp_mapping.techniques_by_tactic()

        lines.append("| Tactic | Technique ID | Technique Name | Confidence | Severity | Matched On |")
        lines.append("|--------|-------------|----------------|------------|----------|------------|")

        for tactic in MitreTactic:
            matches = by_tactic.get(tactic, [])
            if not matches:
                continue
            # 기법별 중복 제거 (최고 confidence만)
            best_by_tech: dict[str, TTPMatch] = {}
            for m in matches:
                tid = m.technique.technique_id
                if tid not in best_by_tech or m.confidence > best_by_tech[tid].confidence:
                    best_by_tech[tid] = m

            for m in best_by_tech.values():
                lines.append(
                    f"| {tactic.name} | `{m.technique.technique_id}` | "
                    f"{m.technique.name} | {m.confidence:.0%} | "
                    f"{m.technique.severity_weight:.2f} | {m.matched_on} |"
                )

        return "\n".join(lines)

    def _render_rule_analysis(self) -> str:
        lines = ["## 6. Detection Rule Analysis", ""]

        if self.gap_analysis:
            lines.append(f"### 6.1 Coverage Summary")
            lines.append("")
            lines.append(f"- 식별된 기법 수: {self.gap_analysis.total_techniques_seen}")
            lines.append(f"- 기존 룰 커버: {self.gap_analysis.covered}")
            lines.append(f"- 누락 기법: {self.gap_analysis.gap_count}")
            lines.append(f"- 커버리지: {self.gap_analysis.coverage_rate:.0%}")

        if self.generated_rules:
            lines.append("")
            lines.append("### 6.2 Auto-Generated Rules")
            lines.append("")
            lines.append("| Rule ID | Name | MITRE ID | Severity | Conditions |")
            lines.append("|---------|------|----------|----------|------------|")

            for rule in self.generated_rules:
                conds = "; ".join(
                    f"{f} {o} {v}" for f, o, v in rule.conditions
                )
                if len(conds) > 60:
                    conds = conds[:57] + "..."
                lines.append(
                    f"| `{rule.rule_id}` | {rule.name} | "
                    f"`{rule.mitre_technique_id}` | {rule.severity:.2f} | {conds} |"
                )
        elif self.gap_analysis and self.gap_analysis.gap_count == 0:
            lines.append("")
            lines.append("모든 식별된 기법에 대한 탐지 룰이 존재합니다.")

        return "\n".join(lines)

    def _render_retro_findings(self) -> str:
        lines = ["## 7. Retro Hunt Findings", ""]

        if not self.retro_results:
            lines.append("레트로 헌트가 실행되지 않았습니다.")
            return "\n".join(lines)

        total_matches = sum(r.match_count for r in self.retro_results)
        total_scanned = sum(r.total_events_scanned for r in self.retro_results)

        lines.append(f"총 **{total_scanned}**건의 과거 이벤트를 스캔하여 "
                     f"**{total_matches}**건의 추가 위협을 발견했습니다.")
        lines.append("")
        lines.append("| Rule | Scanned | Matches | Match Rate | Duration |")
        lines.append("|------|---------|---------|------------|----------|")

        for result in self.retro_results:
            lines.append(
                f"| `{result.rule.rule_id}` | {result.total_events_scanned} | "
                f"{result.match_count} | {result.match_rate:.2%} | "
                f"{result.scan_duration_ms:.1f}ms |"
            )

        # 주요 발견 이벤트 (최대 10건)
        if total_matches > 0:
            lines.append("")
            lines.append("### 주요 발견 이벤트")
            lines.append("")
            count = 0
            for result in self.retro_results:
                for match in result.matches[:5]:
                    if count >= 10:
                        break
                    evt = match.event
                    lines.append(
                        f"- **{match.event_timestamp}** — "
                        f"`{evt.get('action', 'N/A')}` by "
                        f"`{evt.get('identity', 'N/A')}` "
                        f"(Rule: `{result.rule.rule_id}`)"
                    )
                    count += 1

        return "\n".join(lines)

    def _render_impact(self) -> str:
        lines = ["## 8. Impact Assessment", ""]

        if not self.ttp_mapping or not self.ttp_mapping.matches:
            lines.append("영향 범위를 평가할 수 없습니다.")
            return "\n".join(lines)

        # 고유 identity 수
        identities = {e.get("identity", "") for e in self.events if e.get("identity")}
        source_ips = {e.get("source_ip", "") for e in self.events if e.get("source_ip")}
        resources = {e.get("resource", "") for e in self.events if e.get("resource")}
        regions = {e.get("region", "") for e in self.events if e.get("region")}

        lines.append(f"- **영향받은 계정**: {len(identities)}개")
        lines.append(f"- **관련 소스 IP**: {len(source_ips)}개")
        lines.append(f"- **영향받은 리소스**: {len(resources)}개")
        lines.append(f"- **영향받은 리전**: {len(regions)}개")

        # 심각도 판정
        max_sev = self.ttp_mapping.max_severity
        coverage = self.ttp_mapping.kill_chain_coverage
        retro_matches = sum(r.match_count for r in self.retro_results)

        if max_sev >= 0.9 or coverage >= 0.5:
            self.severity = "CRITICAL"
            lines.append("")
            lines.append("> **CRITICAL**: 즉각적인 대응이 필요합니다.")
        elif max_sev >= 0.7 or coverage >= 0.3:
            self.severity = "HIGH"
            lines.append("")
            lines.append("> **HIGH**: 긴급 조사 및 조치가 필요합니다.")
        elif max_sev >= 0.5 or retro_matches > 10:
            self.severity = "MEDIUM"
        else:
            self.severity = "LOW"

        return "\n".join(lines)

    def _render_recommendations(self) -> str:
        lines = ["## 9. Recommendations", ""]

        rec_num = 1

        # 룰 갭 관련
        if self.gap_analysis and self.gap_analysis.gap_count > 0:
            lines.append(
                f"{rec_num}. **탐지 룰 배포**: {self.gap_analysis.gap_count}개의 "
                f"자동 생성 룰을 검증 후 프로덕션에 배포하세요."
            )
            rec_num += 1

        # TTP 관련
        if self.ttp_mapping:
            tactics = self.ttp_mapping.tactics_involved
            if any(t == MitreTactic.DEFENSE_EVASION for t in tactics):
                lines.append(
                    f"{rec_num}. **로깅 무결성 확인**: Defense Evasion 전술이 감지되었습니다. "
                    f"CloudTrail/로깅 설정이 변조되지 않았는지 즉시 확인하세요."
                )
                rec_num += 1

            if any(t == MitreTactic.PERSISTENCE for t in tactics):
                lines.append(
                    f"{rec_num}. **계정 감사**: Persistence 전술이 감지되었습니다. "
                    f"최근 생성/수정된 IAM 사용자, 역할, 정책을 감사하세요."
                )
                rec_num += 1

            if any(t == MitreTactic.EXFILTRATION for t in tactics):
                lines.append(
                    f"{rec_num}. **데이터 유출 확인**: Exfiltration 전술이 감지되었습니다. "
                    f"스냅샷 공유, S3 버킷 접근 로그를 검토하세요."
                )
                rec_num += 1

            if any(t == MitreTactic.CREDENTIAL_ACCESS for t in tactics):
                lines.append(
                    f"{rec_num}. **자격 증명 교체**: Credential Access가 감지되었습니다. "
                    f"관련 계정의 액세스 키와 비밀번호를 즉시 교체하세요."
                )
                rec_num += 1

        # 레트로 헌트 관련
        retro_matches = sum(r.match_count for r in self.retro_results)
        if retro_matches > 0:
            lines.append(
                f"{rec_num}. **과거 침해 조사**: 레트로 헌트에서 {retro_matches}건의 "
                f"과거 이벤트가 발견되었습니다. 침해 시작 시점을 확인하고 "
                f"영향 범위를 재평가하세요."
            )
            rec_num += 1

        # 일반 권고
        lines.append(
            f"{rec_num}. **지속 모니터링**: 향후 24시간 동안 관련 계정과 "
            f"리소스에 대한 강화된 모니터링을 유지하세요."
        )

        return "\n".join(lines)
