"""密评自查（gmscope.audit）：检查项库 + path/op/value 三态 DSL 引擎。"""

from .dsl import VERDICT_FAIL, VERDICT_NA, VERDICT_PARTIAL, VERDICT_PASS
from .engine import CHECKS_PATH, EXAMPLES, load_checks, load_example, run_audit, run_audit_file

__all__ = [
    "CHECKS_PATH",
    "EXAMPLES",
    "VERDICT_FAIL",
    "VERDICT_NA",
    "VERDICT_PARTIAL",
    "VERDICT_PASS",
    "load_checks",
    "load_example",
    "run_audit",
    "run_audit_file",
]
