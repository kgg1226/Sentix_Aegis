"""TTP Mapper — CloudEvent/DetectionSignal을 MITRE ATT&CK 기법에 매핑.

탐지된 이벤트를 분석하여 해당하는 MITRE ATT&CK Tactic/Technique을 식별한다.
기존 attack_knowledge.py의 KillChainPhase와 연동하되,
실제 MITRE ATT&CK 매트릭스 ID(T-코드)를 사용한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


# ---------------------------------------------------------------------------
# MITRE ATT&CK Tactic (Enterprise Matrix)
# ---------------------------------------------------------------------------

class MitreTactic(Enum):
    """MITRE ATT&CK Enterprise 전술 14개."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class MitreTechnique:
    """단일 MITRE ATT&CK 기법."""

    technique_id: str             # e.g. "T1078"
    name: str                     # e.g. "Valid Accounts"
    tactic: MitreTactic
    description: str
    detection_keywords: tuple[str, ...]    # 이벤트에서 매칭할 키워드
    cloud_actions: tuple[str, ...]         # CloudEvent.action 매칭 패턴
    severity_weight: float = 0.5  # 0.0-1.0, 위험도 가중치


# ---------------------------------------------------------------------------
# Cloud ATT&CK Technique Library
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: list[MitreTechnique] = [
    # --- Reconnaissance ---
    MitreTechnique(
        technique_id="T1595",
        name="Active Scanning",
        tactic=MitreTactic.RECONNAISSANCE,
        description="Adversary scans victim infrastructure to gather information",
        detection_keywords=("scan", "probe", "enumerate", "discovery"),
        cloud_actions=("DescribeInstances", "ListBuckets", "GetCallerIdentity"),
        severity_weight=0.3,
    ),

    # --- Initial Access ---
    MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Adversary uses legitimate credentials to gain access",
        detection_keywords=("login", "auth", "console_login", "signin"),
        cloud_actions=("ConsoleLogin", "AssumeRole", "GetSessionToken"),
        severity_weight=0.6,
    ),
    MitreTechnique(
        technique_id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Use compromised cloud service accounts",
        detection_keywords=("cloud_login", "federated", "sso", "iam_user"),
        cloud_actions=("ConsoleLogin", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"),
        severity_weight=0.7,
    ),
    MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Exploit vulnerability in internet-facing application",
        detection_keywords=("exploit", "injection", "rce", "vulnerability"),
        cloud_actions=(),
        severity_weight=0.8,
    ),

    # --- Execution ---
    MitreTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic=MitreTactic.EXECUTION,
        description="Abuse command-line interpreters for execution",
        detection_keywords=("command", "script", "invoke", "execute", "lambda"),
        cloud_actions=("InvokeFunction", "RunCommand", "StartAutomationExecution"),
        severity_weight=0.6,
    ),

    # --- Persistence ---
    MitreTechnique(
        technique_id="T1098",
        name="Account Manipulation",
        tactic=MitreTactic.PERSISTENCE,
        description="Modify accounts to maintain access",
        detection_keywords=("create_user", "add_key", "attach_policy", "create_role"),
        cloud_actions=(
            "CreateUser", "CreateAccessKey", "AttachUserPolicy",
            "AttachRolePolicy", "PutUserPolicy", "CreateLoginProfile",
        ),
        severity_weight=0.8,
    ),
    MitreTechnique(
        technique_id="T1136",
        name="Create Account",
        tactic=MitreTactic.PERSISTENCE,
        description="Create new account for persistent access",
        detection_keywords=("create_user", "create_account", "add_user"),
        cloud_actions=("CreateUser", "CreateServiceAccount", "CreateIAMUser"),
        severity_weight=0.7,
    ),

    # --- Privilege Escalation ---
    MitreTechnique(
        technique_id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        description="Bypass privilege elevation controls",
        detection_keywords=("escalation", "privilege", "sudo", "admin", "root"),
        cloud_actions=("AttachRolePolicy", "PutRolePolicy", "CreatePolicyVersion"),
        severity_weight=0.9,
    ),

    # --- Defense Evasion ---
    MitreTechnique(
        technique_id="T1562",
        name="Impair Defenses",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Disable or modify security tools/logging",
        detection_keywords=("disable", "stop_logging", "delete_trail", "modify_rule"),
        cloud_actions=(
            "StopLogging", "DeleteTrail", "DisableRule",
            "DeleteFlowLogs", "DeleteDetector", "UpdateDetector",
        ),
        severity_weight=0.95,
    ),
    MitreTechnique(
        technique_id="T1562.008",
        name="Impair Defenses: Disable Cloud Logs",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Disable cloud logging to cover tracks",
        detection_keywords=("stop_logging", "delete_trail", "disable_log"),
        cloud_actions=("StopLogging", "DeleteTrail", "PutEventSelectors"),
        severity_weight=1.0,
    ),

    # --- Credential Access ---
    MitreTechnique(
        technique_id="T1528",
        name="Steal Application Access Token",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Steal OAuth tokens or API keys",
        detection_keywords=("token", "secret", "credential", "key", "password"),
        cloud_actions=("GetSecretValue", "GetParameter", "ListSecrets"),
        severity_weight=0.8,
    ),

    # --- Discovery ---
    MitreTechnique(
        technique_id="T1580",
        name="Cloud Infrastructure Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Enumerate cloud resources and configurations",
        detection_keywords=("describe", "list", "get", "enumerate"),
        cloud_actions=(
            "DescribeInstances", "ListBuckets", "DescribeSecurityGroups",
            "ListRoles", "ListUsers", "GetAccountAuthorizationDetails",
        ),
        severity_weight=0.4,
    ),

    # --- Lateral Movement ---
    MitreTechnique(
        technique_id="T1550",
        name="Use Alternate Authentication Material",
        tactic=MitreTactic.LATERAL_MOVEMENT,
        description="Use stolen tokens/credentials for lateral movement",
        detection_keywords=("assume_role", "cross_account", "lateral", "pivot"),
        cloud_actions=("AssumeRole", "GetFederationToken", "SwitchRole"),
        severity_weight=0.7,
    ),

    # --- Collection ---
    MitreTechnique(
        technique_id="T1530",
        name="Data from Cloud Storage",
        tactic=MitreTactic.COLLECTION,
        description="Access data from cloud storage (S3, Blob, etc.)",
        detection_keywords=("download", "get_object", "read_data", "storage"),
        cloud_actions=("GetObject", "ListObjectsV2", "CopyObject", "HeadObject"),
        severity_weight=0.6,
    ),

    # --- Exfiltration ---
    MitreTechnique(
        technique_id="T1537",
        name="Transfer Data to Cloud Account",
        tactic=MitreTactic.EXFILTRATION,
        description="Transfer data to adversary-controlled cloud account",
        detection_keywords=("transfer", "copy", "exfil", "export", "snapshot"),
        cloud_actions=(
            "CopySnapshot", "ModifySnapshotAttribute",
            "ShareSnapshot", "CreateSnapshot", "ModifyImageAttribute",
        ),
        severity_weight=0.9,
    ),

    # --- Command and Control ---
    MitreTechnique(
        technique_id="T1102",
        name="Web Service",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Use web services for C2 communication",
        detection_keywords=("c2", "beacon", "callback", "tunnel"),
        cloud_actions=(),
        severity_weight=0.7,
    ),

    # --- Impact ---
    MitreTechnique(
        technique_id="T1485",
        name="Data Destruction",
        tactic=MitreTactic.IMPACT,
        description="Destroy data and backups",
        detection_keywords=("delete", "destroy", "wipe", "remove", "terminate"),
        cloud_actions=(
            "DeleteBucket", "DeleteObject", "TerminateInstances",
            "DeleteDBInstance", "DeleteSnapshot",
        ),
        severity_weight=1.0,
    ),
    MitreTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic=MitreTactic.IMPACT,
        description="Encrypt data for ransom or disruption",
        detection_keywords=("encrypt", "ransom", "lock", "kms"),
        cloud_actions=("DisableKey", "ScheduleKeyDeletion", "PutBucketEncryption"),
        severity_weight=1.0,
    ),
]


# ---------------------------------------------------------------------------
# TTP Match Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TTPMatch:
    """단일 TTP 매칭 결과."""

    technique: MitreTechnique
    confidence: float           # 0.0-1.0
    matched_on: str             # 매칭 근거 (action/keyword/indicator)
    event_id: str               # 원본 이벤트 ID


@dataclass(slots=True)
class TTPMapping:
    """전체 이벤트 세트에 대한 TTP 매핑 결과."""

    matches: list[TTPMatch] = field(default_factory=list)

    @property
    def tactics_involved(self) -> list[MitreTactic]:
        """관련된 전술 목록 (중복 제거, 순서 보존)."""
        seen: set[MitreTactic] = set()
        result: list[MitreTactic] = []
        for m in self.matches:
            if m.technique.tactic not in seen:
                seen.add(m.technique.tactic)
                result.append(m.technique.tactic)
        return result

    @property
    def kill_chain_coverage(self) -> float:
        """킬 체인 커버리지 — 전술 14개 중 몇 개가 매칭되었는지."""
        return len(self.tactics_involved) / len(MitreTactic)

    @property
    def max_severity(self) -> float:
        """가장 높은 severity_weight."""
        if not self.matches:
            return 0.0
        return max(m.technique.severity_weight for m in self.matches)

    def techniques_by_tactic(self) -> dict[MitreTactic, list[TTPMatch]]:
        """전술별 매칭 그룹화."""
        result: dict[MitreTactic, list[TTPMatch]] = {}
        for m in self.matches:
            result.setdefault(m.technique.tactic, []).append(m)
        return result


# ---------------------------------------------------------------------------
# TTP Mapper
# ---------------------------------------------------------------------------

class TTPMapper:
    """CloudEvent를 MITRE ATT&CK TTP에 매핑하는 엔진.

    두 가지 매칭 전략:
    1. Action 매칭: CloudEvent.action이 technique의 cloud_actions에 포함
    2. Keyword 매칭: 이벤트 필드에서 detection_keywords 탐색
    """

    def __init__(self, techniques: list[MitreTechnique] | None = None) -> None:
        self._techniques = techniques or MITRE_TECHNIQUES
        # action -> technique 인덱스 (빠른 조회)
        self._action_index: dict[str, list[MitreTechnique]] = {}
        for tech in self._techniques:
            for action in tech.cloud_actions:
                self._action_index.setdefault(action.lower(), []).append(tech)

    def map_event(
        self,
        event_id: str,
        action: str,
        detail: str = "",
        indicators: dict[str, str] | None = None,
    ) -> list[TTPMatch]:
        """단일 이벤트를 TTP에 매핑.

        Args:
            event_id: 이벤트 고유 ID
            action: CloudEvent.action (예: "ConsoleLogin", "StopLogging")
            detail: 추가 컨텍스트 (DetectionSignal.detail 등)
            indicators: IOC 딕셔너리

        Returns:
            매칭된 TTP 리스트 (confidence 내림차순)
        """
        matches: list[TTPMatch] = []
        action_lower = action.lower()
        detail_lower = detail.lower()
        searchable = f"{action_lower} {detail_lower}"
        if indicators:
            searchable += " " + " ".join(indicators.values()).lower()

        for tech in self._techniques:
            confidence = 0.0
            matched_on = ""

            # Strategy 1: exact action match (high confidence)
            if action_lower in [a.lower() for a in tech.cloud_actions]:
                confidence = max(confidence, 0.85)
                matched_on = f"action:{action}"

            # Strategy 2: keyword match
            keyword_hits = sum(
                1 for kw in tech.detection_keywords if kw in searchable
            )
            if keyword_hits > 0:
                kw_conf = min(0.75, 0.25 + keyword_hits * 0.15)
                if kw_conf > confidence:
                    confidence = kw_conf
                    hit_kws = [kw for kw in tech.detection_keywords if kw in searchable]
                    matched_on = f"keywords:{','.join(hit_kws)}"

            if confidence > 0.0:
                matches.append(TTPMatch(
                    technique=tech,
                    confidence=confidence,
                    matched_on=matched_on,
                    event_id=event_id,
                ))

        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def map_events(
        self,
        events: list[dict],
    ) -> TTPMapping:
        """여러 이벤트를 일괄 매핑.

        Args:
            events: list of dicts with keys: event_id, action, detail, indicators

        Returns:
            TTPMapping with all matches
        """
        mapping = TTPMapping()
        seen: set[tuple[str, str]] = set()  # (event_id, technique_id) 중복 방지

        for evt in events:
            matches = self.map_event(
                event_id=evt.get("event_id", "unknown"),
                action=evt.get("action", ""),
                detail=evt.get("detail", ""),
                indicators=evt.get("indicators"),
            )
            for m in matches:
                key = (m.event_id, m.technique.technique_id)
                if key not in seen:
                    seen.add(key)
                    mapping.matches.append(m)

        return mapping
