"""
ai_agent.py
GRC Compliance Assessment Tool - AI Gap Analysis Engine
7005SCN Individual Research Project - Segun Akinsoyinu
Coventry University MSc Cyber Security

Uses Claude Haiku via Anthropic API with structured tool_use output.
tool_use forces the API to return output matching a defined JSON schema,
eliminating JSON parsing errors at the API level rather than catching them
with try/except after the fact.

Note: Claude API is used in this prototype due to hardware constraints
in the research environment. A production deployment would substitute
a locally hosted model (e.g. Llama 3.1 8B via Ollama) to maintain
on-premises data privacy.
"""

import os
import anthropic
from database import (
    get_controls_for_question, save_finding, get_saved_control_ids,
    get_all_control_ids, get_mapped_control_ids
)

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


def _truncate(text, max_words=40):
    """
    Hard-cap AI-generated text at max_words words.

    The 40-word limit is instructed in the prompt but Claude Haiku does not
    reliably enforce it for complex nmap-based or multi-requirement controls.
    This function enforces the limit at the code level before any text reaches
    the database or the report, regardless of how verbose the API response is.
    """
    if not text:
        return text
    words = text.split()
    if len(words) <= max_words:
        return text
    truncated = ' '.join(words[:max_words])
    if not truncated[-1] in '.!?':
        truncated += '...'
    return truncated

MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = """You are a certified GRC (Governance, Risk and Compliance) analyst
specialising in UK cybersecurity and data protection regulations. You assess small and
medium-sized enterprise (SME) responses against three specific frameworks:

1. Cyber Essentials v3.1 (NCSC) - UK government-backed technical security baseline
2. GDPR Article 32 (UK) - Technical and organisational security measures for personal data
3. ISO/IEC 27001:2022 Annex A - International information security controls

Your assessments must be:
- Factual and based only on what the organisation has stated
- Referenced to the specific control being assessed
- Practical and actionable for a non-technical SME audience
- Concise but complete

You must call the provided tool to record your findings. Do not respond with plain text."""


# -------------------------------------------------- Tool schema (structured output)
# Defining the schema here forces the Anthropic API to validate Claude's output
# before returning it. This is architecturally superior to parsing raw JSON
# because invalid output is rejected at the API level, not caught after the fact.

FINDING_TOOL = {
    "name": "record_compliance_findings",
    "description": (
        "Record structured compliance assessment findings for each control evaluated. "
        "Must be called once per assessment with all findings included."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "One finding object per control assessed",
                "items": {
                    "type": "object",
                    "properties": {
                        "control_id": {
                            "type": "string",
                            "description": "The exact control ID e.g. CE-FW-2, GDPR-32-1, ISO-A.8.5"
                        },
                        "framework": {
                            "type": "string",
                            "enum": ["Cyber Essentials", "GDPR Article 32", "ISO 27001:2022"],
                            "description": "Exact framework name - must use one of the three enum values"
                        },
                        "status": {
                            "type": "string",
                            "enum": ["compliant", "partial", "non-compliant"],
                            "description": (
                                "compliant: answer fully satisfies the requirement. "
                                "partial: some effort shown but requirement not fully met. "
                                "non-compliant: answer clearly fails the requirement."
                            )
                        },
                        "gap_description": {
                            "type": ["string", "null"],
                            "description": "Specific gap identified against this control. Null if compliant."
                        },
                        "recommendation": {
                            "type": ["string", "null"],
                            "description": "Actionable recommendation for the SME. Null if fully compliant."
                        }
                    },
                    "required": ["control_id", "framework", "status", "gap_description", "recommendation"]
                }
            }
        },
        "required": ["findings"]
    }
}

NMAP_FINDING_TOOL = {
    "name": "record_nmap_findings",
    "description": (
        "Record structured compliance findings derived from Nmap network scan evidence. "
        "Each finding must reference specific ports or services detected in the scan."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "control_id": {
                            "type": "string"
                        },
                        "framework": {
                            "type": "string",
                            "enum": ["Cyber Essentials", "GDPR Article 32", "ISO 27001:2022"]
                        },
                        "status": {
                            "type": "string",
                            "enum": ["compliant", "partial", "non-compliant"]
                        },
                        "gap_description": {
                            "type": ["string", "null"]
                        },
                        "recommendation": {
                            "type": ["string", "null"]
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Specific port/service from the scan that supports this finding"
                        }
                    },
                    "required": ["control_id", "framework", "status",
                                 "gap_description", "recommendation", "evidence"]
                }
            }
        },
        "required": ["findings"]
    }
}


# ---------------------------------------------------------------- Core functions

def assess_response(question_text, answer, controls,
                    nmap_evidence=None, patch_evidence=None):
    """
    Assess a single questionnaire response against all mapped controls.

    Uses tool_use to force structured output from the API.
    The API validates the response schema before returning - no JSON parsing needed.

    Args:
        question_text: The question that was asked
        answer: The organisation's answer
        controls: List of control dicts mapped to this question
        nmap_evidence: Optional Nmap summary string
        patch_evidence: Optional patch management summary string

    Returns:
        List of finding dicts, one per control
    """
    if not controls:
        return []

    controls_text = ""
    for ctrl in controls:
        controls_text += (
            f"\nControl ID: {ctrl['control_id']}"
            f"\nFramework: {ctrl['framework']}"
            f"\nControl Name: {ctrl['control_name']}"
            f"\nRequirement: {ctrl['description']}\n"
        )

    evidence_text = ""
    if nmap_evidence:
        evidence_text += f"\nNetwork Scan Evidence (technical):\n{nmap_evidence}"
        # The same banner caution the nmap pass carries. Controls outside
        # network_control_ids still receive the scan summary when they share a
        # question with one that is inside it, which is how ISO-A.8.14 and
        # ISO-A.8.24 came to cite Windows Server 2008 R2 and Windows 7 from an SMB
        # banner on a lab running Server 2022 and Windows 10.
        evidence_text += (
            "\nCAUTION: service banner product strings, particularly SMB and NetBIOS, "
            "report the range of Windows releases compatible with the observed "
            "protocol dialect, not the operating system of the host. Never infer, "
            "name or cite a host operating system from a service banner, and never "
            "treat a banner version range as evidence of an end-of-life system."
        )
    if patch_evidence:
        evidence_text += f"\nHost Evidence (technical, collected by agent):\n{patch_evidence}"

    prompt = (
        f"Assess the following SME questionnaire response against each control listed.\n\n"
        f"QUESTION ASKED:\n{question_text}\n\n"
        f"ORGANISATION'S ANSWER:\n{answer}\n"
        f"{evidence_text}\n"
        f"CONTROLS TO ASSESS:\n{controls_text}\n"
        f"Answer semantics:\n"
        f"- This is a self-assessment questionnaire. The answer is one of 'yes', 'no', "
        f"or 'partial' and is a self-attestation; it cannot include supporting documents.\n"
        f"- 'yes' means the organisation attests it meets the requirement. Treat 'yes' as "
        f"compliant UNLESS the technical evidence above contradicts it. Do not downgrade "
        f"a 'yes' merely because no documentary proof accompanies it.\n"
        f"- 'partial' means the organisation itself admits the requirement is only partly "
        f"met: classify as partial.\n"
        f"- 'no' means the requirement is not met: classify as non-compliant.\n"
        f"Rules:\n"
        f"- If technical evidence contradicts the answer, base status on the evidence and "
        f"say so in the gap description\n"
        f"- Gap descriptions must be specific to this control, not generic\n"
        f"- Gap descriptions must be 2-3 sentences maximum (40 words maximum)\n"
        f"- Set gap_description and recommendation to null when the control is compliant\n"
        f"- Recommendations must be actionable for a non-technical SME\n"
        f"- Recommendations must be 2-3 sentences maximum (40 words maximum)\n"
        f"- Call the record_compliance_findings tool with one finding per control listed"
    )

    message = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[FINDING_TOOL],
        tool_choice={"type": "tool", "name": "record_compliance_findings"},
        messages=[{"role": "user", "content": prompt}]
    )

    # Extract structured output - no JSON parsing required
    # The API enforces the schema before returning
    for block in message.content:
        if block.type == "tool_use" and block.name == "record_compliance_findings":
            return block.input.get("findings", [])

    return []


def run_full_assessment(assessment_id, responses,
                        nmap_evidence=None, patch_evidence=None):
    """
    Run gap analysis for all questionnaire responses in an assessment.

    Args:
        assessment_id: Database ID of the assessment
        responses: List of dicts with keys: question_id, question_text, answer
        nmap_evidence: Optional dict with 'summary' key
        patch_evidence: Optional patch summary string

    Returns:
        Summary dict with counts per framework
    """
    summary = {
        "Cyber Essentials": {"compliant": 0, "partial": 0, "non-compliant": 0},
        "GDPR Article 32":  {"compliant": 0, "partial": 0, "non-compliant": 0},
        "ISO 27001:2022":   {"compliant": 0, "partial": 0, "non-compliant": 0},
    }

    # Pre-populate with controls already saved by assess_nmap_findings().
    # This ensures nmap technical evidence takes precedence over self-reported
    # questionnaire answers and prevents duplicate rows in the report.
    processed_controls = get_saved_control_ids(assessment_id)

    # Every control_id defined in the database. Findings naming anything else are
    # rejected rather than written (see _record below).
    valid_control_ids = get_all_control_ids()

    # The question context each control was offered under, so any control the model
    # omits from its response can be re-queried with the same evidence it should
    # have seen the first time.
    control_context = {}

    # Controls the Nmap scan can speak to. The GDPR entries were previously absent,
    # so no GDPR control ever received network evidence even though Table 3.1 maps
    # GDPR-32-2 to the exposed FTP service, GDPR-32-3 to Telnet, GDPR-32-6 to SMBv1
    # and the disabled firewall, and GDPR-32-9 to exposed RDP and VNC. Those controls
    # were therefore classified from self-report alone and missed.
    network_control_ids = {
        "CE-FW-1", "CE-FW-2", "CE-FW-4",
        "ISO-A.8.20", "ISO-A.8.21", "ISO-A.8.22",
        "GDPR-32-2", "GDPR-32-3", "GDPR-32-6", "GDPR-32-9",
    }
    # Controls the PowerShell agent's host evidence can speak to. The agent collects
    # patch history, firewall state per profile, local user accounts, password policy
    # and listening ports, so its evidence is relevant well beyond patch management.
    # Previously only the four patch controls received it, so firewall state and the
    # enabled Guest account were collected, transmitted and then never shown to the
    # model, leaving those controls classified from self-report alone.
    host_evidence_control_ids = {
        # patch currency
        "CE-PM-1", "CE-PM-2", "CE-PM-3", "CE-PM-4", "ISO-A.8.8", "ISO-A.8.19",
        # firewall state per profile
        "CE-FW-1", "CE-FW-2", "CE-FW-4", "ISO-A.8.20",
        # local accounts, including enabled Guest account
        "CE-SC-2", "CE-UAC-1", "CE-UAC-2", "ISO-A.5.16", "ISO-A.5.18", "ISO-A.8.2",
        # password policy (net accounts)
        "CE-UAC-5", "ISO-A.5.17",
        # RDP Network Level Authentication. Only the remote-access controls are
        # listed: CE-UAC-3 concerns MFA for cloud services, which RDP evidence
        # says nothing about, so it is deliberately excluded rather than given
        # evidence that does not support it.
        "CE-UAC-4", "ISO-A.8.5",
    }

    def _record(findings, nmap_ctx, patch_ctx):
        """Validate and persist a batch of findings. Returns the number saved."""
        for finding in findings:
            ctrl_id = finding.get("control_id")
            if not ctrl_id or ctrl_id in processed_controls:
                continue

            # Reject any control_id that is not a real control. Foreign keys are
            # not enforced, so save_finding() would write it, and the inner JOIN
            # in get_findings() would then hide it from the report while leaving
            # it in the database to be counted by analysis queries. The model has
            # been observed returning the framework name ("GDPR Article 32") in
            # this field, which is how assessments 10 and 13 came to hold 52 rows
            # while their PDFs showed 51.
            if ctrl_id not in valid_control_ids:
                print(f"[ai] rejected finding for unknown control_id {ctrl_id!r}")
                continue

            processed_controls.add(ctrl_id)

            framework = finding.get("framework", "")
            status    = finding.get("status", "non-compliant")
            gap_desc  = _truncate(finding.get("gap_description"))
            rec       = _truncate(finding.get("recommendation"))

            # Record which evidence sources were actually presented to the model for
            # this control, so agent-verified findings can be counted separately from
            # self-reported ones during the RQ1 and RQ2 analysis.
            sources = ["questionnaire"]
            if nmap_ctx:
                sources.append("nmap")
            if patch_ctx:
                sources.append("host_agent")

            save_finding(
                assessment_id=assessment_id,
                control_id=ctrl_id,
                framework=framework,
                status=status,
                gap_description=gap_desc,
                recommendation=rec,
                evidence_source="+".join(sources)
            )

            fw_key = next((k for k in summary if k in framework), None)
            if fw_key and status in summary[fw_key]:
                summary[fw_key][status] += 1

    for resp in responses:
        question_id   = resp["question_id"]
        question_text = resp["question_text"]
        answer        = resp["answer"]

        controls = get_controls_for_question(question_id)
        if not controls:
            continue

        control_ids = {c["control_id"] for c in controls}

        # Filter to only controls not yet assessed (by nmap or earlier questions).
        # This prevents Claude receiving controls it has already seen, which caused
        # it to return only the dominant control (e.g. ISO-A.8.5) and silently
        # omit the others (CE-UAC-3, CE-UAC-4, ISO-A.5.23).
        new_controls = [c for c in controls if c["control_id"] not in processed_controls]
        if not new_controls:
            continue

        # nmap/patch context decision uses the full control_ids set for the question
        # so the context is still provided even when some controls are already processed.
        nmap_ctx = (
            nmap_evidence.get("summary", "")
            if nmap_evidence and control_ids & network_control_ids
            else None
        )
        patch_ctx = (
            patch_evidence
            if patch_evidence and control_ids & host_evidence_control_ids
            else None
        )

        # Remember what each control was offered with, for the completeness pass.
        for ctrl in new_controls:
            control_context[ctrl["control_id"]] = (
                question_text, answer, ctrl, nmap_ctx, patch_ctx
            )

        findings = assess_response(
            question_text=question_text,
            answer=answer,
            controls=new_controls,
            nmap_evidence=nmap_ctx,
            patch_evidence=patch_ctx
        )

        _record(findings, nmap_ctx, patch_ctx)

    # Completeness pass. The model is asked for one finding per control but does not
    # always return them all, and an omitted control is silently absent from the
    # report. That shrinks the denominator the RQ1 and RQ2 metrics are computed over
    # without producing any error, so every control that was offered and not returned
    # is re-queried once, on its own, with the same question and evidence.
    missing = [cid for cid in control_context if cid not in processed_controls]
    if missing:
        print(f"[ai] model omitted {len(missing)} control(s), re-querying: {sorted(missing)}")
        retries = {}
        for cid in missing:
            q_text, ans, ctrl, nmap_ctx, patch_ctx = control_context[cid]
            retries.setdefault((q_text, ans, nmap_ctx, patch_ctx), []).append(ctrl)

        for (q_text, ans, nmap_ctx, patch_ctx), ctrls in retries.items():
            _record(
                assess_response(
                    question_text=q_text,
                    answer=ans,
                    controls=ctrls,
                    nmap_evidence=nmap_ctx,
                    patch_evidence=patch_ctx
                ),
                nmap_ctx, patch_ctx
            )

        still_missing = [cid for cid in control_context if cid not in processed_controls]
        if still_missing:
            print(f"[ai] WARNING: still missing after retry: {sorted(still_missing)}")

    expected = get_mapped_control_ids()
    print(f"[ai] assessment {assessment_id}: "
          f"{len(processed_controls & expected)}/{len(expected)} mapped controls assessed")

    return summary


def assess_nmap_findings(assessment_id, nmap_findings):
    """
    Assess Nmap scan results directly against network-related controls.
    Uses the dedicated NMAP_FINDING_TOOL schema for structured output.

    Args:
        assessment_id: Database ID of the assessment
        nmap_findings: Dict from nmap_parser
    """
    if not nmap_findings or nmap_findings.get("error"):
        return

    prompt = (
        f"Assess these Nmap network scan results against the controls listed below.\n\n"
        f"SCAN RESULTS:\n"
        f"Open Ports: {nmap_findings.get('open_ports', [])}\n"
        f"Services Detected: {nmap_findings.get('services', [])}\n"
        f"Dangerous Services: {nmap_findings.get('dangerous_services', [])}\n"
        f"OS Information: {nmap_findings.get('os_info', [])}\n"
        f"End-of-Life OS Detected: {nmap_findings.get('eol_os_detected', [])}\n\n"
        f"CONTROLS TO ASSESS:\n"
        f"- CE-FW-2 (Cyber Essentials): Default deny inbound - are unnecessary ports open?\n"
        f"- CE-FW-4 (Cyber Essentials): Block insecure services - is Telnet, FTP, or SMBv1 exposed?\n"
        f"- CE-PM-1 (Cyber Essentials): Licensed and supported software - any EOL OS detected?\n"
        f"- ISO-A.8.20 (ISO 27001:2022): Network security - is network exposure appropriate for an SME?\n"
        f"- ISO-A.8.22 (ISO 27001:2022): Network segregation - is there evidence of segmentation?\n\n"
        f"Base each finding strictly on what the scan evidence shows. "
        f"Reference specific ports and services in your evidence field. "
        f"Nmap OS detection is probabilistic. Do not state an operating system "
        f"version as confirmed, and do not name any operating system that does not "
        f"appear verbatim in the evidence above. If the end-of-life list is empty, "
        f"do not claim end-of-life systems are present. "
        f"Service banner product strings, particularly SMB and NetBIOS, report the "
        f"range of Windows releases compatible with the observed protocol dialect, "
        f"not the operating system of the host. Never infer, name or cite a host "
        f"operating system from a service banner, and never treat a banner version "
        f"range as evidence of an end-of-life system. "
        f"Gap descriptions must be 2-3 sentences maximum (40 words maximum). "
        f"Recommendations must be 2-3 sentences maximum (40 words maximum). "
        f"Call the record_nmap_findings tool with all findings."
    )

    message = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[NMAP_FINDING_TOOL],
        tool_choice={"type": "tool", "name": "record_nmap_findings"},
        messages=[{"role": "user", "content": prompt}]
    )

    valid_control_ids = get_all_control_ids()

    for block in message.content:
        if block.type == "tool_use" and block.name == "record_nmap_findings":
            for finding in block.input.get("findings", []):
                ctrl_id = finding.get("control_id")
                # Same validation as the questionnaire pass: a control_id that is
                # not a real control would be written without complaint and then
                # hidden from the report by the inner JOIN in get_findings().
                if not ctrl_id or ctrl_id not in valid_control_ids:
                    print(f"[ai] rejected nmap finding for unknown control_id {ctrl_id!r}")
                    continue
                save_finding(
                    assessment_id=assessment_id,
                    control_id=ctrl_id,
                    framework=finding.get("framework", ""),
                    status=finding.get("status", "non-compliant"),
                    gap_description=_truncate(finding.get("gap_description")),
                    recommendation=_truncate(finding.get("recommendation")),
                    evidence_source="nmap_scan"
                )
            return


if __name__ == "__main__":
    import json

    test_controls = [
        {
            "control_id":   "CE-FW-2",
            "framework":    "Cyber Essentials",
            "control_name": "Default Deny Inbound",
            "description":  "The default firewall rule must deny all inbound connections "
                            "unless explicitly permitted.",
            "category":     "Firewalls"
        }
    ]
    findings = assess_response(
        question_text="Does your firewall block all inbound connections by default?",
        answer="No, we use the default settings on our router.",
        controls=test_controls
    )
    print(json.dumps(findings, indent=2))
