#!/usr/bin/env python3
"""
rq1-manual-assessment.py
RQ1 comparison condition: three independent single-framework assessments.

Section 3.6 compares the unified tool against three independent assessments made with
the published NCSC Cyber Essentials self-assessment questionnaire, the ICO GDPR
Article 32 checklist, and the ISO/IEC 27001:2022 Annex A gap analysis template.

Evidence parity (decision A): the manual assessments are conducted against the SAME
technical evidence available to the tool, so the only variable under test is whether
assessment is unified or siloed. Without parity, any difference could be caused by the
presence of evidence rather than by unification.

Usage:
    python3 rq1-manual-assessment.py generate   # writes three blank CSV sheets
    python3 rq1-manual-assessment.py score      # reads them, prints Table 6.1

7005SCN Individual Research Project - Segun Akinsoyinu
"""

import csv
import os
import sqlite3
import sys

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "grc_controls.db")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rq1-manual")

# Which assessment instrument covers which framework. An assessor using one instrument
# sees only that instrument's controls; this siloing is the effect RQ1 measures.
FRAMEWORKS = {
    "Cyber Essentials":  ("CE",   "NCSC Cyber Essentials self-assessment questionnaire"),
    "GDPR Article 32":   ("GDPR", "ICO GDPR Article 32 security checklist"),
    "ISO 27001:2022":    ("ISO",  "ISO/IEC 27001:2022 Annex A gap analysis template"),
}

# Table 3.1 ground truth, CORRECTED: CE-UAC-3 removed from the RDP row because it is the
# cloud-services MFA control and the laboratory contains no cloud services.
# Keyed by misconfiguration so the cross-framework analysis in Section 3.8 can be computed.
GROUND_TRUTH = {
    "FTP service open (port 21)":            ["CE-FW-4", "GDPR-32-2"],
    "Telnet service open (port 23)":         ["CE-FW-2", "CE-FW-4", "ISO-A.8.20", "GDPR-32-3"],
    "RDP without MFA (port 3389)":           ["CE-UAC-4", "ISO-A.8.5", "GDPR-32-9"],
    "SMBv1 enabled (port 445)":              ["CE-FW-4", "ISO-A.8.22", "GDPR-32-6"],
    "VNC exposed (port 5900)":               ["CE-FW-4", "ISO-A.8.20", "GDPR-32-9"],
    "Windows Firewall disabled":             ["CE-FW-1", "CE-FW-2", "ISO-A.8.20", "GDPR-32-6"],
    "Windows Update disabled (Win10)":       ["CE-PM-2", "CE-PM-4", "ISO-A.8.8"],
    "Guest account enabled (Win10)":         ["CE-SC-2", "CE-UAC-2", "ISO-A.5.16"],
}

FRAMEWORK_OF = {"CE": "Cyber Essentials", "GDPR": "GDPR Article 32", "ISO": "ISO 27001:2022"}


def framework_of(control_id):
    return FRAMEWORK_OF[control_id.split("-")[0]]


def gt_controls():
    """Flat set of every control the corrected Table 3.1 expects to fail."""
    return {c for ids in GROUND_TRUTH.values() for c in ids}


def cross_framework_controls():
    """Controls arising from a misconfiguration that spans two or more frameworks.

    Section 3.8's secondary analysis: these are the failures a siloed assessor is most
    likely to miss, because the misconfiguration is visible in one framework's
    vocabulary but its consequences belong to another's.
    """
    out = set()
    for ids in GROUND_TRUTH.values():
        if len({framework_of(c) for c in ids}) >= 2:
            out.update(ids)
    return out


def generate():
    os.makedirs(OUT, exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    gt = gt_controls()

    for framework, (prefix, instrument) in FRAMEWORKS.items():
        rows = conn.execute(
            "SELECT control_id, control_name, category, description FROM controls "
            "WHERE framework = ? ORDER BY control_id", (framework,)
        ).fetchall()

        path = os.path.join(OUT, f"manual-{prefix}.csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([f"INSTRUMENT: {instrument}"])
            w.writerow([f"FRAMEWORK: {framework}  |  {len(rows)} controls"])
            w.writerow(["Complete this sheet in full before opening any other sheet.",
                        "Record only this framework's controls.",
                        "Do not consult Table 3.1 or any tool output."])
            w.writerow([])
            w.writerow(["control_id", "control_name", "category",
                        "checklist_item_used", "verdict", "evidence_cited"])
            for r in rows:
                w.writerow([r["control_id"], r["control_name"], r["category"], "", "", ""])
        print(f"wrote {path}  ({len(rows)} controls, "
              f"{sum(1 for r in rows if r['control_id'] in gt)} in ground truth)")

    conn.close()
    print()
    print("verdict column: write  fail  or  pass  for every control. Leave none blank.")
    print("evidence_cited: the machine fact or checklist answer the verdict rests on.")


def score():
    gt = gt_controls()
    cross = cross_framework_controls()
    manual_fail = set()
    missing_sheets = []

    for framework, (prefix, _) in FRAMEWORKS.items():
        path = os.path.join(OUT, f"manual-{prefix}.csv")
        if not os.path.exists(path):
            missing_sheets.append(path)
            continue
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.reader(f):
                if len(row) >= 5 and row[0].startswith(("CE-", "GDPR-", "ISO-")):
                    if row[4].strip().lower() in ("fail", "f", "non-compliant", "partial"):
                        manual_fail.add(row[0].strip())

    if missing_sheets:
        print("MISSING SHEETS, cannot score:")
        for m in missing_sheets:
            print("  ", m)
        return

    conn = sqlite3.connect(DB)
    aid = conn.execute("SELECT MAX(id) FROM assessments").fetchone()[0]
    tool_fail = {r[0] for r in conn.execute(
        "SELECT control_id FROM assessment_findings WHERE assessment_id = ? "
        "AND status IN ('non-compliant','partial')", (aid,))}
    conn.close()

    print(f"Tool column taken from assessment {aid}. "
          f"Change it in the database query if you want a different run.\n")
    print("Table 6.1: RQ1 Coverage Recall Comparison (Unified Tool vs Independent Assessments)\n")
    hdr = f"{'Framework':<24}{'Independent':>12}{'Unified':>9}{'Cross-FW':>10}{'Recall':>9}"
    print(hdr)
    print("-" * len(hdr))

    tot_i = tot_u = tot_x = tot_n = 0
    for framework, (prefix, _) in FRAMEWORKS.items():
        ids = sorted(c for c in gt if framework_of(c) == framework)
        i = sum(1 for c in ids if c in manual_fail)
        u = sum(1 for c in ids if c in tool_fail)
        x = sum(1 for c in ids if c in cross and c in tool_fail and c not in manual_fail)
        tot_i += i; tot_u += u; tot_x += x; tot_n += len(ids)
        print(f"{framework:<24}{i:>12}{u:>9}{x:>10}{round(100*u/len(ids)):>8}%")
    print("-" * len(hdr))
    print(f"{'TOTAL':<24}{tot_i:>12}{tot_u:>9}{tot_x:>10}{round(100*tot_u/tot_n):>8}%")

    print(f"\nGround truth: {tot_n} controls (Table 3.1 corrected).")
    print(f"Independent combined recall: {tot_i}/{tot_n} = {round(100*tot_i/tot_n)}%")
    print(f"Unified tool recall        : {tot_u}/{tot_n} = {round(100*tot_u/tot_n)}%")

    only_tool = sorted(c for c in gt if c in tool_fail and c not in manual_fail)
    only_man = sorted(c for c in gt if c in manual_fail and c not in tool_fail)
    print(f"\nFound by tool only ({len(only_tool)}): {', '.join(only_tool) or '-'}")
    print(f"Found by manual only ({len(only_man)}): {', '.join(only_man) or '-'}")

    print("\nPer misconfiguration (cross-framework detail for Section 3.8):")
    for mis, ids in GROUND_TRUTH.items():
        fws = {framework_of(c) for c in ids}
        if len(fws) < 2:
            continue
        miss = [c for c in ids if c in tool_fail and c not in manual_fail]
        print(f"  {mis:<34} spans {len(fws)} frameworks | "
              f"tool caught but manual missed: {', '.join(miss) or 'none'}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "generate":
        generate()
    elif mode == "score":
        score()
    else:
        print(__doc__)
