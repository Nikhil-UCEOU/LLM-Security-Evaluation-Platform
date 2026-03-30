from typing import List, Dict, Any


def select_strategy(rca_report: Dict[str, Any], isr: float) -> str:
    """
    Select mitigation strategy based on RCA findings and ISR.
    Returns: 'prompt_hardening' | 'guardrails' | 'combined'
    """
    if isr > 0.5:
        return "combined"

    root_causes = rca_report.get("root_causes", [])
    has_architectural = any(
        "architecture" in rc.get("description", "").lower()
        for rc in root_causes
    )

    if has_architectural:
        return "combined"

    return "prompt_hardening"


def extract_vulnerability_categories(rca_report: Dict[str, Any]) -> List[str]:
    """Extract the list of vulnerability categories from an RCA report."""
    root_causes = rca_report.get("root_causes", [])
    return list({rc.get("category", "") for rc in root_causes if rc.get("category")})
