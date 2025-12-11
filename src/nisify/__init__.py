"""
Nisify - NIST CSF 2.0 Compliance Evidence Aggregator

Testify to your NIST maturity with evidence to prove it.

Nisify is a focused, single-purpose tool that aggregates evidence from cloud
platforms and maps it to NIST CSF 2.0 controls to demonstrate compliance maturity.

Key Features:
    - Connects to cloud platforms via read-only API credentials
    - Pulls evidence artifacts (logs, configurations, policies)
    - Maps evidence to NIST CSF 2.0 controls
    - Calculates maturity scores per function/category/subcategory
    - Identifies gaps with actionable explanations
    - Generates board-ready reports and raw evidence exports

Design Principles:
    - Minimalism: Do one thing well
    - Transparency: Every decision is explainable
    - Portability: Zero vendor lock-in
    - Security: Read-only by design
    - Determinism: No LLM magic, all scoring is auditable
"""

__version__ = "0.1.0"
__author__ = ""
__email__ = ""

from nisify.config.settings import Settings, load_config

__all__ = [
    "__version__",
    "Settings",
    "load_config",
]
