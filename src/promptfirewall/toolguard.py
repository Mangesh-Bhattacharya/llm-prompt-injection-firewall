"""ToolGuard: a policy layer between an LLM agent and its tools.

The text firewall (`PromptFirewall`) answers "does this text look like an
injection?". ToolGuard answers the question that actually bounds the blast
radius: "should this *proposed action* execute?". It enforces, outside the
model:

  * default-deny: a tool with no policy cannot be called;
  * argument contracts: types, ranges, enums, patterns, no unknown arguments;
  * provenance/taint: a privileged call proposed while the model's context
    contained suspicious untrusted text (retrieved docs, tool output, user
    messages) is denied or escalated to a human;
  * step-up approval: destructive tools and over-threshold values always
    require approval, regardless of what the model "decided".

Usage:
    guard = ToolGuard.from_dict(policy_dict)
    decision = guard.evaluate(
        ToolCall("wire_transfer", {"amount": 9500, "to_account": "000123"}),
        untrusted_context=[ticket_text, retrieved_doc],
    )
    if decision.action is not Action.ALLOW:
        ...  # refuse, or queue for human approval
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .detector import AnalysisResult, PromptFirewall, Verdict

audit_logger = logging.getLogger("promptfirewall.audit")

# Bound the work done per call so a hostile payload cannot make the guard
# itself the denial-of-service vector.
MAX_STRING_ARG_LENGTH = 20_000
MAX_UNTRUSTED_ITEMS = 50
MAX_ARGS = 64


class PolicyError(ValueError):
    """Raised when a policy document is malformed. Fail closed at load time."""


class Action(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class Risk(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


_SEVERITY = {Action.ALLOW: 0, Action.REQUIRE_APPROVAL: 1, Action.DENY: 2}
_VERDICT_SEVERITY = {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.BLOCK: 2}

_ARG_TYPES = {"string", "number", "integer", "boolean"}


@dataclass(frozen=True)
class ArgSpec:
    """Contract for one tool argument."""

    type: str = "string"
    required: bool = True
    min: float | None = None
    max: float | None = None
    enum: tuple[Any, ...] | None = None
    pattern: re.Pattern[str] | None = None
    max_length: int = 1_000
    # Scan this string argument with the text firewall (free text is where
    # injected payloads get smuggled; identifiers and enums are not scanned).
    scan: bool = False

    @classmethod
    def from_dict(cls, name: str, raw: Mapping[str, Any]) -> ArgSpec:
        arg_type = raw.get("type", "string")
        if arg_type not in _ARG_TYPES:
            raise PolicyError(f"argument {name!r}: unsupported type {arg_type!r}")
        pattern = raw.get("pattern")
        try:
            compiled = re.compile(pattern) if pattern is not None else None
        except re.error as exc:
            raise PolicyError(f"argument {name!r}: invalid pattern: {exc}") from None
        enum = raw.get("enum")
        return cls(
            type=arg_type,
            required=bool(raw.get("required", True)),
            min=raw.get("min"),
            max=raw.get("max"),
            enum=tuple(enum) if enum is not None else None,
            pattern=compiled,
            max_length=int(raw.get("max_length", 1_000)),
            scan=bool(raw.get("scan", False)),
        )


@dataclass(frozen=True)
class ApprovalThreshold:
    """Escalate to a human when a numeric argument exceeds `above`."""

    arg: str
    above: float


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    risk: Risk = Risk.READ
    enabled: bool = True
    args: Mapping[str, ArgSpec] = field(default_factory=dict)
    require_approval: bool = False
    approval_thresholds: tuple[ApprovalThreshold, ...] = ()

    @classmethod
    def from_dict(cls, name: str, raw: Mapping[str, Any]) -> ToolPolicy:
        try:
            risk = Risk(raw.get("risk", "read"))
        except ValueError:
            raise PolicyError(f"tool {name!r}: unknown risk {raw.get('risk')!r}") from None
        args = {a: ArgSpec.from_dict(a, spec) for a, spec in raw.get("args", {}).items()}
        thresholds = tuple(
            ApprovalThreshold(arg=t["arg"], above=float(t["above"]))
            for t in raw.get("approval_thresholds", [])
        )
        for t in thresholds:
            if t.arg not in args:
                raise PolicyError(f"tool {name!r}: threshold on undeclared argument {t.arg!r}")
            if args[t.arg].type not in {"number", "integer"}:
                raise PolicyError(f"tool {name!r}: threshold argument {t.arg!r} is not numeric")
        return cls(
            name=name,
            risk=risk,
            enabled=bool(raw.get("enabled", True)),
            args=args,
            require_approval=bool(raw.get("require_approval", False)),
            approval_thresholds=thresholds,
        )


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    action: Action
    tool: str
    reasons: list[str] = field(default_factory=list)
    risk: Risk | None = None
    context_verdict: Verdict = Verdict.ALLOW
    argument_verdict: Verdict = Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "tool": self.tool,
            "risk": self.risk.value if self.risk else None,
            "reasons": self.reasons,
            "context_verdict": self.context_verdict.value,
            "argument_verdict": self.argument_verdict.value,
        }


AuditSink = Callable[[dict[str, Any]], None]


class ToolGuard:
    def __init__(
        self,
        policies: Sequence[ToolPolicy],
        firewall: PromptFirewall | None = None,
        audit_sink: AuditSink | None = None,
    ):
        self._policies = {p.name: p for p in policies}
        if len(self._policies) != len(policies):
            raise PolicyError("duplicate tool names in policy")
        self._firewall = firewall or PromptFirewall()
        self._audit_sink = audit_sink

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any], **kwargs: Any) -> ToolGuard:
        tools = doc.get("tools")
        if not isinstance(tools, Mapping):
            raise PolicyError("policy must contain a 'tools' object")
        return cls([ToolPolicy.from_dict(n, raw) for n, raw in tools.items()], **kwargs)

    @classmethod
    def from_file(cls, path: str, **kwargs: Any) -> ToolGuard:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"cannot load policy {path!r}: {exc}") from None
        return cls.from_dict(doc, **kwargs)

    @property
    def tool_names(self) -> list[str]:
        return sorted(self._policies)

    def evaluate(
        self,
        call: ToolCall,
        untrusted_context: Sequence[str] = (),
    ) -> Decision:
        decision = self._evaluate(call, untrusted_context)
        self._audit(decision, call)
        return decision

    # -- internals ---------------------------------------------------------

    def _evaluate(self, call: ToolCall, untrusted_context: Sequence[str]) -> Decision:
        policy = self._policies.get(call.name)
        if policy is None:
            return Decision(Action.DENY, call.name, ["no policy for tool (default deny)"])
        if not policy.enabled:
            return Decision(Action.DENY, call.name, ["tool disabled by policy"], policy.risk)

        decision = Decision(Action.ALLOW, call.name, risk=policy.risk)

        def escalate(action: Action, reason: str) -> None:
            decision.reasons.append(reason)
            if _SEVERITY[action] > _SEVERITY[decision.action]:
                decision.action = action

        if len(untrusted_context) > MAX_UNTRUSTED_ITEMS:
            escalate(Action.DENY, f"too many context items (>{MAX_UNTRUSTED_ITEMS})")
            return decision

        self._check_arguments(policy, call, escalate)
        if decision.action is Action.DENY:
            return decision

        self._scan_arguments(policy, call, decision, escalate)
        self._scan_context(policy, untrusted_context, decision, escalate)

        if policy.risk is Risk.DESTRUCTIVE:
            escalate(Action.REQUIRE_APPROVAL, "destructive tool always requires approval")
        if policy.require_approval:
            escalate(Action.REQUIRE_APPROVAL, "policy requires approval for this tool")
        for t in policy.approval_thresholds:
            value = call.arguments.get(t.arg)
            is_num = isinstance(value, (int, float)) and not isinstance(value, bool)
            if is_num and value > t.above:
                escalate(
                    Action.REQUIRE_APPROVAL,
                    f"{t.arg}={value} exceeds approval threshold {t.above:g}",
                )
        return decision

    def _check_arguments(
        self,
        policy: ToolPolicy,
        call: ToolCall,
        escalate: Callable[[Action, str], None],
    ) -> None:
        args = call.arguments
        if len(args) > MAX_ARGS:
            escalate(Action.DENY, f"too many arguments (>{MAX_ARGS})")
            return
        for name in args:
            if name not in policy.args:
                escalate(Action.DENY, f"unexpected argument {name!r}")
        for name, spec in policy.args.items():
            if name not in args:
                if spec.required:
                    escalate(Action.DENY, f"missing required argument {name!r}")
                continue
            problem = _validate_value(spec, args[name])
            if problem:
                escalate(Action.DENY, f"argument {name!r}: {problem}")

    def _scan_arguments(
        self,
        policy: ToolPolicy,
        call: ToolCall,
        decision: Decision,
        escalate: Callable[[Action, str], None],
    ) -> None:
        for name, spec in policy.args.items():
            value = call.arguments.get(name)
            if not spec.scan or not isinstance(value, str):
                continue
            result = self._firewall.analyze(value)
            if _VERDICT_SEVERITY[result.verdict] > _VERDICT_SEVERITY[decision.argument_verdict]:
                decision.argument_verdict = result.verdict
            if result.verdict is Verdict.BLOCK:
                escalate(Action.DENY, f"argument {name!r} contains injection ({_signals(result)})")
            elif result.verdict is Verdict.FLAG and policy.risk is not Risk.READ:
                escalate(Action.REQUIRE_APPROVAL, f"argument {name!r} is suspicious")

    def _scan_context(
        self,
        policy: ToolPolicy,
        untrusted_context: Sequence[str],
        decision: Decision,
        escalate: Callable[[Action, str], None],
    ) -> None:
        worst = Verdict.ALLOW
        for text in untrusted_context:
            if not isinstance(text, str):
                continue
            result = self._firewall.analyze(text[:MAX_STRING_ARG_LENGTH])
            if _VERDICT_SEVERITY[result.verdict] > _VERDICT_SEVERITY[worst]:
                worst = result.verdict
        decision.context_verdict = worst
        # Read-only tools can't change state, so tainted context doesn't gate them.
        if policy.risk is Risk.READ:
            return
        if worst is Verdict.BLOCK:
            escalate(Action.DENY, "privileged call proposed from context containing injection")
        elif worst is Verdict.FLAG:
            escalate(Action.REQUIRE_APPROVAL, "privileged call proposed from suspicious context")

    def _audit(self, decision: Decision, call: ToolCall) -> None:
        record = {"event": "toolguard.decision", **decision.to_dict()}
        # Argument names only: values may hold PII or secrets.
        record["arguments"] = sorted(call.arguments)
        audit_logger.info(json.dumps(record, sort_keys=True))
        if self._audit_sink is not None:
            try:
                self._audit_sink(record)
            except Exception:  # a broken sink must never change an authorization result
                audit_logger.exception("audit sink failed")


def _signals(result: AnalysisResult) -> str:
    names = [m.name for m in result.matched_patterns] + [h.name for h in result.heuristic_signals]
    return ", ".join(names) or f"score {result.risk_score}"


def _validate_value(spec: ArgSpec, value: Any) -> str | None:
    """Return a problem description, or None if the value satisfies the spec."""
    if spec.type == "string":
        if not isinstance(value, str):
            return "expected string"
        if len(value) > min(spec.max_length, MAX_STRING_ARG_LENGTH):
            return "too long"
        if spec.pattern is not None and not spec.pattern.fullmatch(value):
            return "does not match required pattern"
    elif spec.type == "boolean":
        if not isinstance(value, bool):
            return "expected boolean"
    else:
        # bool is an int subclass; reject it explicitly.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"expected {spec.type}"
        if spec.type == "integer" and isinstance(value, float) and not value.is_integer():
            return "expected integer"
        if value != value or value in (float("inf"), float("-inf")):
            return "must be finite"
        if spec.min is not None and value < spec.min:
            return f"below minimum {spec.min:g}"
        if spec.max is not None and value > spec.max:
            return f"above maximum {spec.max:g}"
    if spec.enum is not None and value not in spec.enum:
        return "not in allowed values"
    return None
