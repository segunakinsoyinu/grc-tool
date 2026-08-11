"""
main.py
GRC Compliance Assessment Tool - FastAPI Application
7005SCN Individual Research Project - Segun Akinsoyinu
Coventry University MSc Cyber Security

Endpoints:
  GET  /                      - Web interface (HTML form)
  GET  /api/questions         - List all questionnaire questions
  POST /api/assessment/start  - Create a new assessment
  POST /api/assessment/{id}/submit - Submit questionnaire responses
  GET  /api/assessment/{id}/report - Get gap analysis report
  GET  /report/{id}           - HTML report view
"""

import os
import sys
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

from database import (
    init_db, get_questions, create_assessment,
    save_response, get_findings, get_assessment, complete_assessment,
    set_assessment_status, get_saved_control_ids
)
from ai_agent import run_full_assessment, assess_nmap_findings
from parsers.nmap_parser import parse_nmap_xml
from parsers.patch_parser import parse_patch_csv

# Initialise database on startup
init_db()

app = FastAPI(
    title="GRC Compliance Assessment Tool",
    description="Unified compliance assessment for UK SMEs across Cyber Essentials v3.1, "
                "GDPR Article 32, and ISO/IEC 27001:2022 Annex A",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR  = os.path.join(os.path.dirname(__file__), "data")
NMAP_PATH = os.path.join(DATA_DIR, "nmap-scan.xml")
PATCH_PATH = os.path.join(DATA_DIR, "patches.csv")

# --- Stage A automation config ---
NMAP_TARGETS = os.environ.get("NMAP_TARGETS", "10.0.2.20 10.0.2.30")
# NOTE: -O (OS detection) needs root. setcap does NOT work for this on Nmap 7.80:
# the capabilities are granted but nmap still tests geteuid() directly and refuses.
# The working approach is a sudoers rule granting NOPASSWD on nmap only, so the
# command below runs under "sudo -n":
#   /etc/sudoers.d/grc-nmap (mode 440):  <user> ALL=(root) NOPASSWD: /usr/bin/nmap
# --host-timeout is deliberately NOT used. Nmap exits 0 when it abandons a host on
# timeout, so a timeout would look like a successful scan and produce an assessment
# with no network evidence. A slow scan is preferable to a silently empty one; the
# subprocess timeout below is the real upper bound.
NMAP_CMD = os.environ.get(
    "NMAP_CMD",
    "sudo -n nmap -sV -O -p 21,22,23,80,443,445,3389,5900 -oX {out} {targets}"
)
# If true, an assessment waits for the Windows agent's host evidence before the AI runs.
# Set WAIT_FOR_AGENT=0 to fall back to nmap + questionnaire only (no agent).
WAIT_FOR_AGENT = os.environ.get("WAIT_FOR_AGENT", "1") == "1"

# In-memory store of assessments awaiting host evidence.
# (single-run lab use; cleared on server restart)
PENDING_EVIDENCE = {}


def run_nmap_scan():
    """Run Nmap automatically via subprocess; return parsed results, or None on failure.

    A zero exit code does not prove the scan collected anything. Nmap exits 0 when it
    skips a host, and it will also write a well-formed XML file describing a scan in
    which nothing was found. Both cases must be treated as collection failures rather
    than as a valid empty result, otherwise the assessment silently proceeds on
    questionnaire evidence alone and the report looks complete while being wrong.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    cmd = NMAP_CMD.format(out=NMAP_PATH, targets=NMAP_TARGETS).split()
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
    except Exception as e:
        print(f"[nmap] automatic scan failed: {e}")
        return None

    results = parse_nmap_xml(NMAP_PATH)

    if results.get("error"):
        print(f"[nmap] scan output could not be parsed: {results['error']}")
        return None

    if not results.get("open_ports"):
        print(f"[nmap] scan reported no open ports across targets "
              f"'{NMAP_TARGETS}' - treating as a collection failure, not an empty result")
        return None

    return results


def summarise_host_evidence(ev: dict):
    """Turn the PowerShell agent's JSON into a text summary for the AI prompt.
    Patches are written to patches.csv so the existing CE-PM-2 logic is reused."""
    import csv
    lines = []
    if ev.get("patches"):
        with open(PATCH_PATH, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["HotFixID", "Description", "InstalledOn"])
            w.writeheader()
            for p in ev["patches"]:
                w.writerow({"HotFixID": p.get("HotFixID", ""),
                            "Description": p.get("Description", ""),
                            "InstalledOn": p.get("InstalledOn", "")})
        lines.append(parse_patch_csv(PATCH_PATH).get("summary", ""))
    if ev.get("firewall_state"):
        lines.append("Windows Firewall per profile: " +
                     ", ".join(f"{k}={'on' if v else 'OFF'}" for k, v in ev["firewall_state"].items()))
    if ev.get("local_users"):
        active = [u.get("Name") for u in ev["local_users"] if u.get("Enabled")]
        lines.append("Enabled local accounts: " + ", ".join(active))
    if ev.get("password_policy"):
        lines.append("Password policy (net accounts): " + " ".join(str(ev["password_policy"]).split()))
    if ev.get("open_ports"):
        lines.append("Host-reported listening ports: " + ", ".join(str(p) for p in ev["open_ports"]))
    rdp = ev.get("rdp_security") or {}
    if rdp and not rdp.get("error"):
        lines.append(
            "Remote Desktop: enabled=" + ("yes" if rdp.get("rdp_enabled") else "no") +
            ", Network Level Authentication required=" +
            ("yes" if rdp.get("nla_required") else "NO") +
            (". With NLA disabled, remote access requires no authentication before a "
             "session is established." if not rdp.get("nla_required") else "")
        )
    return "\n".join(l for l in lines if l)


# ----------------------------------------------------------------- Pydantic models

class AssessmentStart(BaseModel):
    org_name:     str
    contact_name: str
    sector:       Optional[str] = "Not specified"
    staff_count:  Optional[str] = "Not specified"


class QuestionResponse(BaseModel):
    question_id:   int
    question_text: str
    answer:        str


class SubmitResponses(BaseModel):
    responses: List[QuestionResponse]


# ----------------------------------------------------------------- HTML helpers

def status_badge(status):
    colours = {
        "compliant":     "#2d6a4f",
        "partial":       "#b5451b",
        "non-compliant": "#9b2226",
    }
    labels = {
        "compliant":     "COMPLIANT",
        "partial":       "PARTIAL",
        "non-compliant": "NON-COMPLIANT",
    }
    colour = colours.get(status, "#555")
    label  = labels.get(status, status.upper())
    return (f'<span style="background:{colour};color:#fff;padding:3px 10px;'
            f'border-radius:3px;font-size:12px;font-weight:bold;">{label}</span>')


def framework_colour(framework):
    if "Cyber Essentials" in framework:
        return "#1d3557"
    if "GDPR" in framework:
        return "#457b9d"
    if "ISO" in framework:
        return "#2d6a4f"
    return "#333"


# ----------------------------------------------------------------- Routes

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GRC Compliance Assessment Tool</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Arial, sans-serif; background: #f4f6f8; color: #222; }
    header { background: #1d3557; color: #fff; padding: 24px 40px; }
    header h1 { font-size: 22px; font-weight: bold; }
    header p  { font-size: 13px; color: #a8c8e8; margin-top: 6px; }
    .container { max-width: 820px; margin: 40px auto; padding: 0 20px; }
    .card { background: #fff; border: 1px solid #dde; border-radius: 6px;
            padding: 32px; margin-bottom: 24px; }
    h2 { font-size: 18px; margin-bottom: 16px; color: #1d3557; }
    label { display: block; font-size: 13px; font-weight: bold;
            margin-bottom: 4px; margin-top: 14px; }
    input, select { width: 100%; padding: 9px 12px; border: 1px solid #ccc;
                    border-radius: 4px; font-size: 14px; }
    .btn { display: inline-block; background: #1d3557; color: #fff;
           padding: 11px 28px; border: none; border-radius: 4px;
           font-size: 14px; cursor: pointer; margin-top: 20px; }
    .btn:hover { background: #2a4a7f; }
    .frameworks { display: flex; gap: 12px; margin-top: 16px; flex-wrap: wrap; }
    .fw-badge { padding: 6px 14px; border-radius: 4px; font-size: 12px;
                font-weight: bold; color: #fff; }
    .info { font-size: 13px; color: #555; line-height: 1.6; }
  </style>
</head>
<body>
<header>
  <h1>GRC Compliance Assessment Tool</h1>
  <p>Unified compliance assessment for UK SMEs</p>
</header>
<div class="container">
  <div class="card">
    <h2>About This Tool</h2>
    <p class="info">
      This tool assesses your organisation's compliance posture across three frameworks
      simultaneously from a single questionnaire. It uses AI-assisted gap analysis to
      identify compliance gaps and provide actionable recommendations.
    </p>
    <div class="frameworks">
      <span class="fw-badge" style="background:#1d3557;">Cyber Essentials v3.1</span>
      <span class="fw-badge" style="background:#457b9d;">GDPR Article 32</span>
      <span class="fw-badge" style="background:#2d6a4f;">ISO 27001:2022</span>
    </div>
  </div>

  <div class="card">
    <h2>Start New Assessment</h2>
    <form id="startForm">
      <label>Organisation Name *</label>
      <input type="text" id="org_name" placeholder="e.g. Acme Ltd" required>

      <label>Contact Name *</label>
      <input type="text" id="contact_name" placeholder="e.g. Jane Smith" required>

      <label>Business Sector</label>
      <select id="sector">
        <option value="Not specified">Select sector...</option>
        <option>Retail</option>
        <option>Healthcare</option>
        <option>Professional Services</option>
        <option>Manufacturing</option>
        <option>Finance</option>
        <option>Education</option>
        <option>Construction</option>
        <option>Hospitality</option>
        <option>Technology</option>
        <option>Other</option>
      </select>

      <label>Number of Staff</label>
      <select id="staff_count">
        <option value="Not specified">Select size...</option>
        <option>1-9 (Micro)</option>
        <option>10-49 (Small)</option>
        <option>50-249 (Medium)</option>
      </select>

      <button type="submit" class="btn">Begin Assessment</button>
    </form>
  </div>
</div>

<script>
document.getElementById("startForm").addEventListener("submit", async function(e) {
  e.preventDefault();
  const body = {
    org_name:     document.getElementById("org_name").value,
    contact_name: document.getElementById("contact_name").value,
    sector:       document.getElementById("sector").value,
    staff_count:  document.getElementById("staff_count").value,
  };
  const resp = await fetch("/api/assessment/start", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  const data = await resp.json();
  if (data.assessment_id) {
    window.location.href = "/questionnaire/" + data.assessment_id;
  } else {
    alert("Error starting assessment. Please try again.");
  }
});
</script>
</body>
</html>
""")


@app.get("/questionnaire/{assessment_id}", response_class=HTMLResponse)
async def questionnaire_page(assessment_id: int):
    assessment = get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    questions = get_questions()

    sections = {}
    for q in questions:
        sec = q["section"]
        if sec not in sections:
            sections[sec] = []
        sections[sec].append(q)

    questions_html = ""
    for section, qs in sections.items():
        questions_html += f"""
        <div class="section">
          <h3>{section}</h3>"""
        for q in qs:
            questions_html += f"""
          <div class="question" id="q-block-{q['id']}">
            <p class="q-text">{q['question_text']}</p>"""
            if q.get("help_text"):
                questions_html += f"""
            <p class="help">{q['help_text']}</p>"""
            questions_html += f"""
            <div class="options">
              <label><input type="radio" name="q_{q['id']}" value="yes"> Yes</label>
              <label><input type="radio" name="q_{q['id']}" value="no"> No</label>
              <label><input type="radio" name="q_{q['id']}" value="partial">
                Partially</label>
            </div>
          </div>"""
        questions_html += "</div>"

    return HTMLResponse(content=f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GRC Assessment - Questionnaire</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: Arial, sans-serif; background: #f4f6f8; color: #222; }}
    header {{ background: #1d3557; color: #fff; padding: 20px 40px; }}
    header h1 {{ font-size: 20px; }}
    header p {{ font-size: 13px; color: #a8c8e8; margin-top: 4px; }}
    .container {{ max-width: 820px; margin: 32px auto; padding: 0 20px 60px; }}
    .section {{ background: #fff; border: 1px solid #dde; border-radius: 6px;
               padding: 24px; margin-bottom: 20px; }}
    h3 {{ font-size: 15px; font-weight: bold; color: #1d3557;
          border-bottom: 2px solid #1d3557; padding-bottom: 8px; margin-bottom: 16px; }}
    .question {{ margin-bottom: 20px; padding-bottom: 20px;
                 border-bottom: 1px solid #eee; }}
    .question:last-child {{ border-bottom: none; margin-bottom: 0; padding-bottom: 0; }}
    .q-text {{ font-size: 14px; font-weight: bold; margin-bottom: 6px; }}
    .help {{ font-size: 12px; color: #666; margin-bottom: 8px; line-height: 1.5; }}
    .options {{ display: flex; gap: 20px; }}
    .options label {{ font-size: 13px; display: flex; align-items: center; gap: 6px;
                      cursor: pointer; }}
    .btn {{ display: block; width: 100%; background: #1d3557; color: #fff;
            padding: 14px; border: none; border-radius: 4px; font-size: 15px;
            cursor: pointer; margin-top: 24px; }}
    .btn:hover {{ background: #2a4a7f; }}
    .progress {{ background: #eee; border-radius: 4px; height: 6px; margin: 16px 0; }}
    .progress-bar {{ background: #1d3557; height: 6px; border-radius: 4px;
                     width: 0%; transition: width 0.3s; }}
    #status {{ font-size: 13px; color: #555; text-align: center; margin-top: 8px; }}
    .overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5);
               z-index: 100; align-items: center; justify-content: center; }}
    .overlay.show {{ display: flex; }}
    .spinner-box {{ background: #fff; padding: 40px; border-radius: 8px;
                    text-align: center; max-width: 340px; }}
    .spinner {{ width: 44px; height: 44px; border: 4px solid #eee;
               border-top-color: #1d3557; border-radius: 50%;
               animation: spin 0.8s linear infinite; margin: 0 auto 16px; }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  </style>
</head>
<body>
<header>
  <h1>GRC Compliance Assessment</h1>
  <p>Organisation: {assessment['org_name']} | Assessment ID: {assessment_id}</p>
</header>
<div class="container">
  <div class="progress"><div class="progress-bar" id="pbar"></div></div>
  <div id="status">Answer all questions then click Submit</div>

  <form id="qForm">
    {questions_html}
    <button type="submit" class="btn">Submit Assessment</button>
  </form>
</div>

<div class="overlay" id="overlay">
  <div class="spinner-box">
    <div class="spinner"></div>
    <p style="font-weight:bold;color:#1d3557;margin-bottom:8px;">
      Running AI Gap Analysis
    </p>
    <p style="font-size:13px;color:#555;">
      Assessing your responses against all three frameworks.<br>
      This may take up to 60 seconds.
    </p>
  </div>
</div>

<script>
const totalQs = document.querySelectorAll('.question').length;
document.querySelectorAll('input[type=radio]').forEach(r => {{
  r.addEventListener('change', () => {{
    const answered = new Set(
      [...document.querySelectorAll('input[type=radio]:checked')]
        .map(x => x.name)
    ).size;
    document.getElementById('pbar').style.width = (answered/totalQs*100) + '%';
    document.getElementById('status').textContent =
      answered + ' of ' + totalQs + ' questions answered';
  }});
}});

document.getElementById('qForm').addEventListener('submit', async function(e) {{
  e.preventDefault();
  const responses = [];
  document.querySelectorAll('.question').forEach(block => {{
    const qId = parseInt(block.id.replace('q-block-', ''));
    const qText = block.querySelector('.q-text').textContent;
    const checked = block.querySelector('input[type=radio]:checked');
    if (checked) {{
      responses.push({{
        question_id: qId,
        question_text: qText,
        answer: checked.value
      }});
    }}
  }});

  if (responses.length < totalQs) {{
    alert('Please answer all ' + totalQs + ' questions before submitting.');
    return;
  }}

  document.getElementById('overlay').classList.add('show');

  const resp = await fetch('/api/assessment/{assessment_id}/submit', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{ responses: responses }})
  }});
  const data = await resp.json();
  if (data.status === 'complete') {{
    window.location.href = '/report/' + data.assessment_id;
  }} else if (data.status === 'awaiting_evidence') {{
    // Nmap done; now wait for the Windows agent to POST host evidence and the AI to finish.
    const poll = setInterval(async () => {{
      const s = await (await fetch('/api/assessment/' + data.assessment_id + '/status')).json();
      if (s.status === 'complete') {{
        clearInterval(poll);
        window.location.href = '/report/' + data.assessment_id;
      }}
    }}, 4000);
  }} else {{
    // Surface the server's actual reason (e.g. a failed network scan) rather than a
    // generic message, so a collection failure cannot be mistaken for a transient glitch.
    document.getElementById('overlay').classList.remove('show');
    alert(data.detail || 'Error running assessment. Please try again.');
  }}
}});
</script>
</body>
</html>
""")


@app.get("/api/questions")
async def api_questions():
    return {"questions": get_questions()}


@app.post("/api/assessment/start")
async def start_assessment(data: AssessmentStart):
    assessment_id = create_assessment(
        org_name=data.org_name,
        contact_name=data.contact_name,
        sector=data.sector,
        staff_count=data.staff_count
    )
    return {"assessment_id": assessment_id, "status": "created"}


@app.post("/api/assessment/{assessment_id}/submit")
async def submit_assessment(assessment_id: int, data: SubmitResponses):
    assessment = get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # Reject a repeat submission of the same assessment. The scan takes several minutes
    # and the page shows only a spinner, so a resubmit or a browser retry is easy to
    # trigger. Without this guard the nmap pass runs again and writes a second set of
    # findings for the same controls, producing duplicate rows in the report.
    if assessment.get("status") in ("awaiting_evidence", "complete") \
            or get_saved_control_ids(assessment_id):
        raise HTTPException(
            status_code=409,
            detail=(f"Assessment {assessment_id} has already been submitted "
                    f"(status: {assessment.get('status')}). Start a new assessment "
                    f"rather than resubmitting this one, otherwise the scan runs twice "
                    f"and the report contains duplicate findings.")
        )

    # Save all responses
    for resp in data.responses:
        save_response(assessment_id, resp.question_id, resp.answer)

    responses_for_agent = [
        {
            "question_id":   r.question_id,
            "question_text": r.question_text,
            "answer":        r.answer
        }
        for r in data.responses
    ]

    # 1) Network evidence: run Nmap automatically and assess it first (nmap-first pass).
    #    If collection fails the assessment is abandoned rather than downgraded to a
    #    questionnaire-only run. Continuing would produce a complete-looking report in
    #    which every network control was classified from self-report, which is the exact
    #    failure this tool exists to detect.
    nmap_results = run_nmap_scan()
    if nmap_results is None:
        set_assessment_status(assessment_id, "evidence_failed")
        raise HTTPException(
            status_code=503,
            detail=("Automated network scan failed, so no assessment was produced. "
                    "The assessment was deliberately not completed on questionnaire "
                    "evidence alone. Check the server log for the [nmap] message, "
                    "resolve the cause, then submit again.")
        )

    nmap_evidence = {"summary": nmap_results.get("summary", "")}
    assess_nmap_findings(assessment_id, nmap_results)

    # 2) Wait for the Windows agent's host evidence; the AI runs in /api/upload-evidence
    if WAIT_FOR_AGENT:
        PENDING_EVIDENCE[assessment_id] = {
            "responses": responses_for_agent,
            "nmap_evidence": nmap_evidence
        }
        set_assessment_status(assessment_id, "awaiting_evidence")
        return {"assessment_id": assessment_id, "status": "awaiting_evidence"}

    # 3) Fallback (no agent): assess with nmap + questionnaire only
    summary = run_full_assessment(
        assessment_id=assessment_id,
        responses=responses_for_agent,
        nmap_evidence=nmap_evidence,
        patch_evidence=None
    )
    complete_assessment(assessment_id)
    return {"assessment_id": assessment_id, "status": "complete", "summary": summary}


@app.get("/api/pending-assessment")
async def pending_assessment():
    """The Windows PowerShell agent polls this to find an assessment awaiting host evidence."""
    if not PENDING_EVIDENCE:
        return {"pending": False}
    aid = min(PENDING_EVIDENCE.keys())
    return {"pending": True, "assessment_id": aid, "targets": NMAP_TARGETS.split()}


class EvidenceUpload(BaseModel):
    assessment_id:   int
    hostname:        Optional[str] = None
    patches:         Optional[List[dict]] = None
    firewall_state:  Optional[dict] = None
    local_users:     Optional[List[dict]] = None
    password_policy: Optional[str] = None
    open_ports:      Optional[List[int]] = None
    rdp_security:    Optional[dict] = None


@app.post("/api/upload-evidence")
async def upload_evidence(ev: EvidenceUpload):
    """The agent POSTs host evidence here; the AI assessment then runs and completes."""
    aid = ev.assessment_id
    if aid not in PENDING_EVIDENCE:
        raise HTTPException(status_code=404,
                            detail="No assessment awaiting evidence for this id")
    state = PENDING_EVIDENCE.pop(aid)
    patch_evidence = summarise_host_evidence(ev.dict())
    run_full_assessment(
        assessment_id=aid,
        responses=state["responses"],
        nmap_evidence=state["nmap_evidence"],
        patch_evidence=patch_evidence
    )
    complete_assessment(aid)
    return {"assessment_id": aid, "status": "complete"}


@app.get("/api/assessment/{assessment_id}/status")
async def assessment_status(assessment_id: int):
    a = get_assessment(assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {"assessment_id": assessment_id, "status": a.get("status")}


@app.get("/api/assessment/{assessment_id}/report")
async def api_report(assessment_id: int):
    assessment = get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    findings = get_findings(assessment_id)
    return {"assessment": dict(assessment), "findings": findings}


@app.get("/report/{assessment_id}", response_class=HTMLResponse)
async def html_report(assessment_id: int):
    assessment = get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    findings = get_findings(assessment_id)

    # Group by framework
    by_framework = {}
    for f in findings:
        fw = f["framework"]
        if fw not in by_framework:
            by_framework[fw] = []
        by_framework[fw].append(f)

    # Summary counts
    total   = len(findings)
    comp    = sum(1 for f in findings if f["status"] == "compliant")
    partial = sum(1 for f in findings if f["status"] == "partial")
    non_comp = sum(1 for f in findings if f["status"] == "non-compliant")
    score   = round((comp / total) * 100) if total > 0 else 0

    fw_sections = ""
    for fw, fw_findings in by_framework.items():
        colour = framework_colour(fw)
        fw_comp    = sum(1 for f in fw_findings if f["status"] == "compliant")
        fw_partial = sum(1 for f in fw_findings if f["status"] == "partial")
        fw_nc      = sum(1 for f in fw_findings if f["status"] == "non-compliant")
        fw_total   = len(fw_findings)
        fw_score   = round((fw_comp / fw_total) * 100) if fw_total > 0 else 0

        rows = ""
        for f in fw_findings:
            gap  = f.get("gap_description") or "No gap identified"
            rec  = f.get("recommendation") or "No action required"
            src  = f.get("evidence_source", "questionnaire")
            rows += f"""
            <tr>
              <td style="font-weight:bold;white-space:nowrap;">{f['control_id']}</td>
              <td>{f['control_name']}</td>
              <td>{status_badge(f['status'])}</td>
              <td style="font-size:12px;">{gap}</td>
              <td style="font-size:12px;">{rec}</td>
              <td style="font-size:11px;color:#888;">{src}</td>
            </tr>"""

        fw_sections += f"""
        <div class="fw-section">
          <div class="fw-header" style="border-left:5px solid {colour};">
            <h3 style="color:{colour};">{fw}</h3>
            <div class="fw-counts">
              <span class="ct green">{fw_comp} Compliant</span>
              <span class="ct orange">{fw_partial} Partial</span>
              <span class="ct red">{fw_nc} Non-Compliant</span>
              <span class="ct score">Score: {fw_score}%</span>
            </div>
          </div>
          <div style="overflow-x:auto;">
            <table>
              <thead>
                <tr>
                  <th>Control ID</th>
                  <th>Control</th>
                  <th>Status</th>
                  <th>Gap Identified</th>
                  <th>Recommendation</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""

    return HTMLResponse(content=f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GRC Assessment Report - {assessment['org_name']}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: Arial, sans-serif; background: #f4f6f8; color: #222; }}
    header {{ background: #1d3557; color: #fff; padding: 24px 40px; }}
    header h1 {{ font-size: 20px; }}
    header p {{ font-size: 13px; color: #a8c8e8; margin-top: 4px; }}
    .container {{ max-width: 1100px; margin: 32px auto; padding: 0 20px 60px; }}
    .summary-cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
    .card {{ background: #fff; border: 1px solid #dde; border-radius: 6px; padding: 20px;
             flex: 1; min-width: 140px; }}
    .card h4 {{ font-size: 12px; color: #888; margin-bottom: 8px; text-transform: uppercase; }}
    .card .num {{ font-size: 28px; font-weight: bold; }}
    .green  {{ color: #2d6a4f; }}
    .orange {{ color: #b5451b; }}
    .red    {{ color: #9b2226; }}
    .fw-section {{ background: #fff; border: 1px solid #dde; border-radius: 6px;
                   margin-bottom: 24px; overflow: hidden; }}
    .fw-header {{ padding: 16px 20px; background: #f8f9fa; }}
    .fw-header h3 {{ font-size: 15px; margin-bottom: 8px; }}
    .fw-counts {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .ct {{ font-size: 12px; font-weight: bold; padding: 3px 10px;
           border-radius: 3px; background: #eee; }}
    .ct.green  {{ background: #d8f3dc; color: #2d6a4f; }}
    .ct.orange {{ background: #ffe8d6; color: #b5451b; }}
    .ct.red    {{ background: #fde8e8; color: #9b2226; }}
    .ct.score  {{ background: #1d3557; color: #fff; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: #f0f2f4; text-align: left; padding: 10px 12px;
          font-size: 12px; border-bottom: 2px solid #dde; white-space: nowrap; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #fafafa; }}
    .meta {{ font-size: 12px; color: #666; margin-bottom: 20px; }}
    .btn-pdf {{ display: inline-block; background: #2d6a4f; color: #fff;
               padding: 9px 20px; border-radius: 4px; font-size: 13px;
               text-decoration: none; font-weight: bold; float: right; margin-top: 4px; }}
    .btn-pdf:hover {{ background: #1b4332; }}
    @media print {{ .btn-pdf {{ display: none; }} }}
  </style>
</head>
<body>
<header>
  <h1>GRC Compliance Assessment Report</h1>
  <p>{assessment['org_name']} | {assessment['contact_name']} |
     Generated: {datetime.now().strftime('%d %B %Y %H:%M')}</p>
</header>
<div class="container">
  <p class="meta" style="overflow:hidden;">
    Assessment ID: {assessment_id} |
     Sector: {assessment.get('sector','N/A')} |
     Staff: {assessment.get('staff_count','N/A')} |
     Frameworks: Cyber Essentials v3.1, GDPR Article 32, ISO 27001:2022
    <a href="/report/{assessment_id}/pdf" class="btn-pdf">Download PDF</a>
  </p>

  <div class="summary-cards">
    <div class="card">
      <h4>Overall Score</h4>
      <div class="num">{score}%</div>
    </div>
    <div class="card">
      <h4>Controls Assessed</h4>
      <div class="num">{total}</div>
    </div>
    <div class="card">
      <h4>Compliant</h4>
      <div class="num green">{comp}</div>
    </div>
    <div class="card">
      <h4>Partial</h4>
      <div class="num orange">{partial}</div>
    </div>
    <div class="card">
      <h4>Non-Compliant</h4>
      <div class="num red">{non_comp}</div>
    </div>
  </div>

  {fw_sections}
</div>
</body>
</html>
""")


@app.get("/report/{assessment_id}/pdf")
async def pdf_report(assessment_id: int):
    """
    Generate a PDF download of the assessment report.
    Requires WeasyPrint: pip3 install weasyprint
    Ubuntu system deps: sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0
    """
    try:
        from weasyprint import HTML as WeasyHTML
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail=(
                "PDF generation requires WeasyPrint. "
                "On Ubuntu: sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 "
                "then pip3 install weasyprint"
            )
        )

    assessment = get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    findings = get_findings(assessment_id)

    # Group by framework
    by_framework = {}
    for f in findings:
        fw = f["framework"]
        if fw not in by_framework:
            by_framework[fw] = []
        by_framework[fw].append(f)

    total    = len(findings)
    comp     = sum(1 for f in findings if f["status"] == "compliant")
    partial  = sum(1 for f in findings if f["status"] == "partial")
    non_comp = sum(1 for f in findings if f["status"] == "non-compliant")
    score    = round((comp / total) * 100) if total > 0 else 0

    def pdf_status_badge(status):
        colours = {
            "compliant":     "#2d6a4f",
            "partial":       "#b5451b",
            "non-compliant": "#9b2226",
        }
        labels = {
            "compliant":     "COMPLIANT",
            "partial":       "PARTIAL",
            "non-compliant": "NON-COMPLIANT",
        }
        colour = colours.get(status, "#555")
        label  = labels.get(status, status.upper())
        return (f'<span style="background:{colour};color:#fff;padding:2pt 7pt;'
                f'border-radius:3pt;font-size:8pt;font-weight:bold;">{label}</span>')

    fw_sections = ""
    for fw, fw_findings in by_framework.items():
        fw_comp    = sum(1 for f in fw_findings if f["status"] == "compliant")
        fw_partial = sum(1 for f in fw_findings if f["status"] == "partial")
        fw_nc      = sum(1 for f in fw_findings if f["status"] == "non-compliant")
        fw_total   = len(fw_findings)
        fw_score   = round((fw_comp / fw_total) * 100) if fw_total > 0 else 0

        rows = ""
        for f in fw_findings:
            gap = f.get("gap_description") or "No gap identified"
            rec = f.get("recommendation") or "No action required"
            rows += f"""
            <tr>
              <td><strong>{f['control_id']}</strong></td>
              <td>{f['control_name']}</td>
              <td>{pdf_status_badge(f['status'])}</td>
              <td>{gap}</td>
              <td>{rec}</td>
            </tr>"""

        fw_sections += f"""
        <div class="fw-section">
          <h3>{fw}</h3>
          <p class="fw-meta">Compliant: {fw_comp} | Partial: {fw_partial} |
             Non-Compliant: {fw_nc} | Score: {fw_score}%</p>
          <table>
            <thead>
              <tr>
                <th>Control ID</th><th>Control</th><th>Status</th>
                <th>Gap Identified</th><th>Recommendation</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GRC Assessment Report - {assessment['org_name']}</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #000; font-size: 10.5pt; margin: 0; }}
    h1 {{ font-size: 16pt; margin-bottom: 4pt; }}
    h2 {{ font-size: 12pt; margin: 16pt 0 6pt; border-bottom: 1px solid #000;
          padding-bottom: 3pt; break-after: avoid; page-break-after: avoid; }}
    h3 {{ font-size: 11pt; margin: 0 0 4pt; border-bottom: 2px solid #333;
          padding-bottom: 3pt; break-after: avoid; page-break-after: avoid; }}
    .cover p {{ font-size: 10pt; margin: 3pt 0; }}
    .cover {{ margin-bottom: 18pt; border-bottom: 2px solid #000; padding-bottom: 12pt; }}
    .summary-table {{ width: 100%; border-collapse: collapse; margin-bottom: 18pt; }}
    .summary-table th {{ border: 1px solid #aaa; padding: 6pt; background: #eee;
                         font-size: 9pt; text-align: center; }}
    .summary-table td {{ border: 1px solid #aaa; padding: 6pt; text-align: center;
                         font-size: 11pt; font-weight: bold; }}
    .fw-section {{ margin-bottom: 18pt; }}
    .fw-meta {{ font-size: 9pt; color: #444; margin: 0 0 6pt; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 8.5pt; }}
    th {{ background: #eee; text-align: left; padding: 5pt; border: 1px solid #bbb;
          font-size: 8pt; }}
    td {{ padding: 4pt 5pt; border: 1px solid #ccc; vertical-align: top;
          line-height: 1.4; }}
    tr {{ break-inside: avoid; page-break-inside: avoid; }}
    .footer {{ margin-top: 20pt; font-size: 8pt; color: #666; border-top: 1px solid #ccc;
               padding-top: 6pt; }}
  </style>
</head>
<body>
  <div class="cover">
    <h1>GRC Compliance Assessment Report</h1>
    <p><strong>Organisation:</strong> {assessment['org_name']}</p>
    <p><strong>Contact:</strong> {assessment['contact_name']}</p>
    <p><strong>Sector:</strong> {assessment.get('sector', 'N/A')} |
       <strong>Staff:</strong> {assessment.get('staff_count', 'N/A')}</p>
    <p><strong>Assessment ID:</strong> {assessment_id} |
       <strong>Generated:</strong> {datetime.now().strftime('%d %B %Y %H:%M')}</p>
    <p><strong>Frameworks assessed:</strong> Cyber Essentials v3.1 (NCSC),
       GDPR Article 32 (UK), ISO/IEC 27001:2022 Annex A</p>
  </div>

  <h2>Executive Summary</h2>
  <table class="summary-table">
    <thead>
      <tr>
        <th>Overall Score</th>
        <th>Controls Assessed</th>
        <th>Compliant</th>
        <th>Partial</th>
        <th>Non-Compliant</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>{score}%</td>
        <td>{total}</td>
        <td>{comp}</td>
        <td>{partial}</td>
        <td>{non_comp}</td>
      </tr>
    </tbody>
  </table>

  <h2>Detailed Findings by Framework</h2>
  {fw_sections}

  <div class="footer">
    Generated by GRC Compliance Assessment Tool | 7005SCN Individual Research Project |
    Coventry University MSc Cyber Security | Ethics Reference: P195069
  </div>
</body>
</html>"""

    pdf_bytes = WeasyHTML(string=html_content).write_pdf()

    org_safe  = assessment['org_name'].replace(' ', '_').replace('/', '-')
    filename  = f"GRC_Report_{org_safe}_{assessment_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
