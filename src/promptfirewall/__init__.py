"""promptfirewall — detect and block prompt injection attempts before they reach an LLM."""

from .detector import AnalysisResult, PromptFirewall, Verdict

__all__ = ["PromptFirewall", "Verdict", "AnalysisResult"]
__version__ = "0.1.0"
