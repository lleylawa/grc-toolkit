#!/usr/bin/env python3
"""GRC Data Analysis Toolkit 
Student: Leyla Rakhmatova
Course: Cybersecurity Policy & Risk Management

Part 1: Organizational Profile Analyzer
Part 2: CIA Triad Impact Classifier
"""

from datetime import datetime
from dataclasses import dataclass
from typing import List


def identify_applicable_regulations(org_profile: dict) -> list:
    """Identify regulatory frameworks applicable to an organization profile."""
    regulations = []
    sector = org_profile.get("sector", "").lower()
    employees = org_profile.get("employees", 0)

    if org_profile.get("handles_health_data", False) or sector in ["healthcare", "hospital", "clinic"]:
        regulations.append({
            "name": "HIPAA Security Rule",
            "reason": "Organization handles Protected Health Information (PHI)",
            "priority": "MANDATORY",
            "key_requirement": "Risk analysis and administrative, physical, and technical safeguards",
        })

    if org_profile.get("processes_payments", False):
        regulations.append({
            "name": "PCI-DSS v4.0",
            "reason": "Organization processes, stores, or transmits cardholder data",
            "priority": "MANDATORY",
            "key_requirement": "12 control objectives; annual assessment or SAQ",
        })

    if org_profile.get("handles_eu_personal_data", False):
        regulations.append({
            "name": "GDPR",
            "reason": "Organization processes personal data of EU residents",
            "priority": "MANDATORY",
            "key_requirement": "Lawful basis, data subject rights, and 72-hour breach notification",
        })

    if sector in ["banking", "financial services", "insurance", "fintech"]:
        regulations.append({
            "name": "GLBA Safeguards Rule",
            "reason": "Financial institution subject to Gramm-Leach-Bliley Act",
            "priority": "MANDATORY",
            "key_requirement": "Written information security program; qualified individual to oversee it",
        })

    if org_profile.get("public_company", False):
        regulations.append({
            "name": "SOX IT Controls (Section 404)",
            "reason": "Publicly traded company subject to Sarbanes-Oxley",
            "priority": "MANDATORY",
            "key_requirement": "Annual ICFR assessment; auditor attestation on controls",
        })

    if org_profile.get("is_federal_contractor", False) or sector == "government":
        regulations.append({
            "name": "FISMA / NIST SP 800-53",
            "reason": "Federal agency or contractor subject to FISMA",
            "priority": "MANDATORY",
            "key_requirement": "Authorization to Operate (ATO); continuous monitoring",
        })

    if org_profile.get("handles_cui", False) or sector == "defense":
        regulations.append({
            "name": "CMMC 2.0",
            "reason": "DoD contractor handling Controlled Unclassified Information",
            "priority": "MANDATORY",
            "key_requirement": "CMMC Level 2+ assessment required for DoD contracts",
        })

    if org_profile.get("california_presence", False) and employees >= 1:
        regulations.append({
            "name": "CCPA/CPRA",
            "reason": "Organization does business in California and may meet applicable thresholds",
            "priority": "LIKELY APPLICABLE - verify thresholds",
            "key_requirement": "Consumer rights (access, delete, opt-out); annual data map",
        })

    regulations.append({
        "name": "NIST Cybersecurity Framework 2.0",
        "reason": "Voluntary but widely adopted cybersecurity baseline",
        "priority": "STRONGLY RECOMMENDED",
        "key_requirement": "Govern, Identify, Protect, Detect, Respond, Recover functions",
    })
    return regulations


def assess_governance_maturity(org_profile: dict) -> dict:
    """Score governance, risk, and compliance maturity from 1 to 5."""
    scores = {"governance": 1, "risk": 1, "compliance": 1}
    evidence = {"governance": [], "risk": [], "compliance": []}

    governance_checks = [
        ("has_ciso", 1, "+ CISO or dedicated security leader exists"),
        ("has_security_committee", 1, "+ Security/risk committee established"),
        ("board_security_reporting", 1, "+ Board receives regular security reporting"),
        ("security_budget_defined", 0.5, "+ Defined security budget allocation"),
        ("policy_suite_current", 0.5, "+ Policy suite reviewed within 12 months"),
    ]
    risk_checks = [
        ("has_risk_register", 1, "+ Formal risk register maintained"),
        ("annual_risk_assessment", 1, "+ Annual formal risk assessment conducted"),
        ("continuous_risk_monitoring", 1, "+ Continuous risk monitoring in place"),
        ("risk_appetite_documented", 1, "+ Risk appetite formally documented and approved"),
    ]
    compliance_checks = [
        ("compliance_program", 1, "+ Formal compliance program exists"),
        ("last_audit_passed", 1, "+ Most recent audit passed"),
        ("security_training", 1, "+ Security awareness training program active"),
        ("vendor_risk_program", 1, "+ Third-party/vendor risk assessment program"),
    ]

    for key, points, note in governance_checks:
        if org_profile.get(key, False):
            scores["governance"] += points
            evidence["governance"].append(note)
    for key, points, note in risk_checks:
        if org_profile.get(key, False):
            scores["risk"] += points
            evidence["risk"].append(note)
    for key, points, note in compliance_checks:
        if org_profile.get(key, False):
            scores["compliance"] += points
            evidence["compliance"].append(note)

    for dimension in scores:
        scores[dimension] = min(5, round(scores[dimension], 1))

    return {
        "scores": scores,
        "evidence": evidence,
        "overall_maturity": round(sum(scores.values()) / 3, 1),
    }


def generate_grc_summary_report(org_profile: dict) -> str:
    """Generate a readable GRC readiness report for an organization."""
    regulations = identify_applicable_regulations(org_profile)
    maturity = assess_governance_maturity(org_profile)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = [
        "=" * 65,
        " GRC READINESS ASSESSMENT REPORT",
        f" Organization: {org_profile.get('org_name', 'Unknown')}",
        f" Generated: {now}",
        "=" * 65,
        "APPLICABLE REGULATORY FRAMEWORKS",
        "-" * 65,
    ]

    mandatory = [r for r in regulations if r["priority"] == "MANDATORY"]
    recommended = [r for r in regulations if r["priority"] != "MANDATORY"]

    lines.append(f" MANDATORY ({len(mandatory)} frameworks):")
    for regulation in mandatory:
        lines.append(f"  [REQUIRED] {regulation['name']}")
        lines.append(f"     Reason: {regulation['reason']}")
        lines.append(f"     Key Req: {regulation['key_requirement']}")
        lines.append("")

    if recommended:
        lines.append(f" RECOMMENDED ({len(recommended)} frameworks):")
        for regulation in recommended:
            lines.append(f"  [RECOMMEND] {regulation['name']}")
            lines.append(f"     {regulation['reason']}")
            lines.append("")

    lines += ["GRC MATURITY SCORES (Scale: 1 = Initial -> 5 = Optimizing)", "-" * 65]
    score_display = {1: "Initial/Ad-hoc", 2: "Developing", 3: "Defined", 4: "Managed", 5: "Optimizing"}

    for dimension, score in maturity["scores"].items():
        label = score_display.get(round(score), "N/A")
        bar = "#" * int(score) + "." * (5 - int(score))
        lines.append(f" {dimension.upper():<12} {bar} {score}/5.0 ({label})")
        for item in maturity["evidence"][dimension]:
            lines.append(f"    {item}")

    overall = maturity["overall_maturity"]
    if overall < 2:
        status = "CRITICAL GAPS - IMMEDIATE ACTION NEEDED"
    elif overall < 3:
        status = "DEVELOPING - SIGNIFICANT IMPROVEMENT NEEDED"
    elif overall < 4:
        status = "DEFINED - CONTINUE BUILDING CONSISTENCY"
    else:
        status = "MANAGED - FOCUS ON OPTIMIZATION"

    lines += ["", f" OVERALL GRC MATURITY: {overall}/5.0", f" {status}", "=" * 65]
    return "\n".join(lines)


@dataclass
class SecurityEvent:
    """Simple representation of a cybersecurity event."""
    name: str
    description: str


def classify_cia_impact(event: SecurityEvent) -> dict:
    """Classify a security event by Confidentiality, Integrity, Availability impact."""
    text = f"{event.name.lower()} {event.description.lower()}"

    confidentiality_keywords = [
        "data exposed", "leaked", "unauthorized access", "breach", "exfiltrat",
        "credential", "eavesdrop", "intercept", "disclosed", "stolen", "read",
        "viewed by unauthorized", "ssn",
    ]
    integrity_keywords = [
        "modified", "tampered", "altered", "corrupted", "falsifi", "changed without",
        "forged", "injected", "replaced", "sql inject", "man-in-the-middle",
    ]
    availability_keywords = [
        "unavailable", "down", "outage", "ransomware", "encrypt", "ddos",
        "denial of service", "locked out", "deleted", "wiped", "destroyed", "inaccessible",
    ]

    confidentiality = any(keyword in text for keyword in confidentiality_keywords)
    integrity = any(keyword in text for keyword in integrity_keywords)
    availability_text = text.replace("unencrypted", "")
    availability = any(keyword in availability_text for keyword in availability_keywords)

    if availability:
        primary = "AVAILABILITY"
    elif confidentiality:
        primary = "CONFIDENTIALITY"
    elif integrity:
        primary = "INTEGRITY"
    else:
        primary = "UNCLEAR - manual review needed"

    affected = sum([confidentiality, integrity, availability])
    severity = min(3, affected) if affected > 0 else 1

    return {
        "event": event.name,
        "confidentiality_affected": confidentiality,
        "integrity_affected": integrity,
        "availability_affected": availability,
        "primary_impact": primary,
        "severity": severity,
        "severity_label": {1: "LOW", 2: "MEDIUM", 3: "HIGH"}[severity],
    }


def print_cia_report(events: List[SecurityEvent]) -> None:
    """Print a formatted CIA classification table."""
    print("\n" + "=" * 78)
    print(" CIA TRIAD IMPACT CLASSIFICATION REPORT")
    print("=" * 78)
    print(f" {'EVENT':<28} {'C':^3} {'I':^3} {'A':^3} {'PRIMARY':<16} {'SEV':<6}")
    print("-" * 78)

    for event in events:
        result = classify_cia_impact(event)
        c = "Y" if result["confidentiality_affected"] else "X"
        i = "Y" if result["integrity_affected"] else "X"
        a = "Y" if result["availability_affected"] else "X"
        print(f" {event.name[:26]:<28} {c:^3} {i:^3} {a:^3} {result['primary_impact']:<16} {result['severity_label']:<6}")

    print("=" * 78)
    print(" C=Confidentiality  I=Integrity  A=Availability")


if __name__ == "__main__":
    # Own case company profile. Replace values here if your Lab 1 company differs.
    case_company = {
        "org_name": "Capital Bank",
        "sector": "banking",
        "employees": 500,
        "handles_health_data": False,
        "processes_payments": True,
        "handles_eu_personal_data": False,
        "public_company": False,
        "is_federal_contractor": False,
        "handles_cui": False,
        "california_presence": False,
        "has_ciso": True,
        "has_security_committee": True,
        "board_security_reporting": True,
        "security_budget_defined": True,
        "policy_suite_current": True,
        "has_risk_register": True,
        "annual_risk_assessment": True,
        "continuous_risk_monitoring": True,
        "risk_appetite_documented": True,
        "compliance_program": True,
        "last_audit_passed": True,
        "security_training": True,
        "vendor_risk_program": True,
    }

    print(generate_grc_summary_report(case_company))

    test_events = [
        SecurityEvent("HealthBridge PHI Breach", "Attacker used credential stolen via spyware; 14,200 patient records data exposed to unauthorized party"),
        SecurityEvent("Hospital Ransomware Attack", "All systems encrypted by ransomware; EHR unavailable for 5 days"),
        SecurityEvent("EHR Record Tampering", "Nurse altered medication dosage records in EHR; patient harmed"),
        SecurityEvent("DDoS on Bank Portal", "Customer online banking portal unavailable for 6 hours via DDoS"),
        SecurityEvent("SQL Injection Attack", "Attacker injected SQL into web form; customer records altered"),
        SecurityEvent("Laptop Theft", "Unencrypted laptop with 3,000 employee SSNs stolen from car"),
        SecurityEvent("Insider Data Exfiltration", "Employee emailed 50,000 customer records to personal email before resignation"),
        SecurityEvent("Power Outage", "Data center power outage; no UPS; servers unavailable 3 hours"),
    ]
    print_cia_report(test_events)
