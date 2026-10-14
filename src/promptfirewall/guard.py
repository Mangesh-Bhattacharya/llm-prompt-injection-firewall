"""Agent action guard: taint-aware gating of tool calls.

Scanning text (``PromptFirewall``) answers "does this look like an attack?".
It cannot answer "what is the worst thing that happens if I'm wrong?". This
module covers the second question: once untrusted content (retrieved docs,
tool output, emails) has entered the agent's context, high-impact tools stop
being callable without out-of-band approval — regardless of what the model
*decides* to do next.

    guard = AgentGuard(policies={"search_kb": ToolRisk.LOW, "wire_transfer": ToolRisk.HIGH})
    safe = guard.ingest(doc, source="kb:article-42")   # None if quarantined
    decision = guard.authorize("wire_transfer", {"amount": 5000})
    if decision.action is Action.REQUIRE_APPROVAL: ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .detector import PromptFirewall, Verdict


class ToolRisk(str, Enum):
    LOW = "low"    # read-only / reversible
    HIGH = "high"  # money movement, writes, external side effects, secrets


class Action(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    action: Action
    reason: str


@dataclass
class AgentGuard:
    """Per-session guard. Create one per conversation/task; taint is sticky."""

    firewall: PromptFirewall = field(default_factory=PromptFirewall)
    policies: dict[str, ToolRisk] = field(default_factory=dict)
    # strict=True taints on *any* untrusted content, not just flagged content.
    strict: bool = False
    tainted_by: list[str] = field(default_factory=list)
    quarantined: list[str] = field(default_factory=list)

    @property
    def tainted(self) -> bool:
        return bool(self.tainted_by)

    def ingest(self, text: str, source: str, trusted: bool = False) -> str | None:
        """Scan content before it enters the model context.

        Returns the text if safe to pass on, or ``None`` if quarantined
        (BLOCK). FLAG content is passed through but taints the session.
        """
        if trusted:
            return text
        verdict = self.firewall.analyze(text).verdict
        if verdict is Verdict.BLOCK:
            self.quarantined.append(source)
            self.tainted_by.append(source)
            return None
        if verdict is Verdict.FLAG or self.strict:
            self.tainted_by.append(source)
        return text

    def authorize(self, tool: str, args: dict[str, object] | None = None) -> Decision:
        """Decide whether a model-requested tool call may run."""
        # Secure default: tools without an explicit policy are treated as HIGH.
        risk = self.policies.get(tool, ToolRisk.HIGH)

        for key, value in (args or {}).items():
            if isinstance(value, str) and self.firewall.analyze(value).verdict is Verdict.BLOCK:
                return Decision(Action.DENY, f"argument '{key}' contains an injection payload")

        if risk is ToolRisk.HIGH and self.tainted:
            return Decision(
                Action.REQUIRE_APPROVAL,
                f"high-risk tool '{tool}' requested after untrusted input from "
                f"{', '.join(self.tainted_by)}",
            )
        return Decision(Action.ALLOW, "no tainted context or low-risk tool")
