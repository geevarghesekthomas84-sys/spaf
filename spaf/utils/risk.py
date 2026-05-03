from typing import Optional, Any, Dict
from datetime import datetime

# Severity mappings and orders
SEVERITY_ORDER = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Info": 5
}

CVSS_RANGE = {
    "Critical": "9.0 - 10.0",
    "High": "7.0 - 8.9",
    "Medium": "4.0 - 6.9",
    "Low": "0.1 - 3.9",
    "Info": "0.0"
}

def build_finding(
    target: str,
    vuln_type: str,
    detail: str,
    severity: str,
    recommendation: str,
    scan_type: str,
    extra: Optional[Dict[str, Any]] = None,
    poc: Optional[str] = None
) -> Dict[str, Any]:
    """
    Constructs a standardized finding dictionary.
    """
    if severity not in SEVERITY_ORDER:
        severity = "Info"

    return {
        "target": target,
        "vuln_type": vuln_type,
        "detail": detail,
        "severity": severity,
        "severity_order": SEVERITY_ORDER[severity],
        "cvss_range": CVSS_RANGE[severity],
        "recommendation": recommendation,
        "scan_type": scan_type,
        "extra": extra or {},
        "poc": poc,
        "discovered_at": datetime.utcnow().isoformat(),
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
