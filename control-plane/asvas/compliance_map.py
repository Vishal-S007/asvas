"""Reference mapping of ASVAS controls to common frameworks (requirement DA-12; spec pp. 77-78).

This is a *reference mapping* written by the developers: it says which framework requirements each technical
control is intended to support. It is not an assessment, attestation or certification, and a control appearing
here does not mean the framework requirement is fully met — auditors must evaluate the evidence themselves.

Framework editions: NIST SP 800-53 Rev. 5; ISO/IEC 27001:2022 Annex A; AICPA SOC 2 Trust Services Criteria (2017,
revised points of focus 2022); OWASP ASVS 4.0.3 chapters.
"""

from __future__ import annotations

DISCLAIMER = ("Reference mapping only - not an assessment, attestation or certification. A mapped control supports "
              "but does not by itself satisfy the framework requirement.")
FRAMEWORKS = {"nist_800_53": "NIST SP 800-53 Rev. 5", "iso_27001": "ISO/IEC 27001:2022 Annex A",
              "soc2": "SOC 2 Trust Services Criteria", "owasp_asvs": "OWASP ASVS 4.0.3"}

MAP: dict[str, dict[str, list[str]]] = {
    "audit-chain": {"nist_800_53": ["AU-9", "AU-9(3)", "AU-10"], "iso_27001": ["A.8.15"], "soc2": ["CC7.2"],
                    "owasp_asvs": ["V7.3"]},
    "audit-export": {"nist_800_53": ["AU-9(2)", "AU-11"], "iso_27001": ["A.8.15", "A.5.33"], "soc2": ["CC7.2"],
                     "owasp_asvs": ["V7.3"]},
    "sso-mfa": {"nist_800_53": ["IA-2", "IA-2(1)", "IA-2(2)", "IA-5"], "iso_27001": ["A.5.17", "A.8.5"],
                "soc2": ["CC6.1"], "owasp_asvs": ["V2.8", "V3.5"]},
    "approval-signatures": {"nist_800_53": ["AU-10", "CM-3"], "iso_27001": ["A.8.32"], "soc2": ["CC8.1"],
                            "owasp_asvs": ["V6.2"]},
    "dual-control": {"nist_800_53": ["AC-5"], "iso_27001": ["A.5.3"], "soc2": ["CC6.3"], "owasp_asvs": ["V4.1"]},
    "encryption-at-rest": {"nist_800_53": ["SC-28", "SC-28(1)", "SC-12"], "iso_27001": ["A.8.24"],
                           "soc2": ["CC6.1"], "owasp_asvs": ["V6.2", "V6.4"]},
    "transport-tls": {"nist_800_53": ["SC-8", "SC-8(1)"], "iso_27001": ["A.8.20", "A.8.24"], "soc2": ["CC6.7"],
                      "owasp_asvs": ["V9.1", "V9.2"]},
    "emergency-stop": {"nist_800_53": ["IR-4"], "iso_27001": ["A.5.26"], "soc2": ["CC7.4"], "owasp_asvs": []},
    "policy-engine": {"nist_800_53": ["AC-3", "AC-6"], "iso_27001": ["A.5.15", "A.8.3"], "soc2": ["CC6.1"],
                      "owasp_asvs": ["V4.1"]},
    "retention": {"nist_800_53": ["AU-11", "SI-12"], "iso_27001": ["A.8.10"], "soc2": ["CC6.5"],
                  "owasp_asvs": ["V8.3"]},
    "long-term-memory": {"nist_800_53": ["SC-4", "AC-4"], "iso_27001": ["A.8.11", "A.8.3"], "soc2": ["C1.1"],
                         "owasp_asvs": ["V8.3"]},
    "isolation": {"nist_800_53": ["SC-39", "SC-7"], "iso_27001": ["A.8.22"], "soc2": ["CC6.6"], "owasp_asvs": []},
}


def for_control(cid: str) -> dict[str, list[str]]:
    return MAP.get(cid, {})


def rows_for_export(controls: list[dict]) -> list[dict[str, str]]:
    out = []
    for c in controls:
        for fw, ids in for_control(c["id"]).items():
            for i in ids:
                out.append({"control": c["id"], "requirement": c["requirement"], "status": c["status"],
                            "framework": FRAMEWORKS[fw], "framework_ref": i, "detail": c["detail"]})
    return out
