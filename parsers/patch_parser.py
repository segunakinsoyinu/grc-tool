r"""
parsers/patch_parser.py
GRC Compliance Assessment Tool - Windows Patch CSV Parser
7005SCN Individual Research Project - Segun Akinsoyinu
Coventry University MSc Cyber Security

Parses Windows patch management data exported via PowerShell Get-HotFix.
Assesses patch currency against Cyber Essentials v3.1 14-day patching requirement
and ISO 27001:2022 A.8.8 vulnerability management control.

Export command on Windows Server 2022:
  Get-HotFix | Select-Object HotFixID, Description, InstalledOn |
  Export-Csv -Path C:\patches.csv -NoTypeInformation
"""

import csv
import os
from datetime import datetime, timedelta


# Maximum days since patch release allowed by Cyber Essentials v3.1
CE_PATCH_DEADLINE_DAYS = 14


def parse_patch_csv(csv_path):
    """
    Parse a Windows Get-HotFix CSV export.

    Args:
        csv_path: Path to the patches.csv file

    Returns:
        Dict with keys:
            patches: list of all patch dicts
            total_patches: count of patches found
            recent_patches: patches installed within 14 days
            overdue_patches: patches older than 14 days (potential CE-PM-2 violation)
            oldest_patch: date of the oldest installed patch
            newest_patch: date of the most recent patch
            days_since_last_patch: days since most recent patch
            compliant: bool - True if last patch is within 14 days
            summary: human-readable summary string
    """
    if not os.path.exists(csv_path):
        return {
            "error": f"Patch CSV not found at {csv_path}",
            "patches": [], "total_patches": 0,
            "recent_patches": [], "overdue_patches": [],
            "oldest_patch": None, "newest_patch": None,
            "days_since_last_patch": None, "compliant": False,
            "summary": "No patch data available"
        }

    patches = []
    today = datetime.now()

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Handle different column name formats from Get-HotFix
            hotfix_id   = (row.get("HotFixID") or row.get("HotfixId") or
                           row.get("hotfixid") or "").strip()
            description = (row.get("Description") or row.get("description") or "").strip()
            installed_on = (row.get("InstalledOn") or row.get("installedon") or "").strip()

            if not hotfix_id:
                continue

            # Parse the date - Windows exports in various formats
            install_date = None
            date_formats = [
                "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
                "%m/%d/%Y",
                "%d/%m/%Y",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
            ]
            for fmt in date_formats:
                try:
                    install_date = datetime.strptime(installed_on.strip(), fmt)
                    break
                except (ValueError, AttributeError):
                    continue

            days_old = (today - install_date).days if install_date else None

            patches.append({
                "hotfix_id":    hotfix_id,
                "description":  description,
                "installed_on": installed_on,
                "install_date": install_date,
                "days_old":     days_old
            })

    if not patches:
        return {
            "patches": [], "total_patches": 0,
            "recent_patches": [], "overdue_patches": [],
            "oldest_patch": None, "newest_patch": None,
            "days_since_last_patch": None, "compliant": False,
            "summary": "No patches found in CSV file"
        }

    # Sort by date
    patches_with_dates = [p for p in patches if p["install_date"] is not None]
    patches_with_dates.sort(key=lambda x: x["install_date"])

    oldest = patches_with_dates[0]["install_date"] if patches_with_dates else None
    newest = patches_with_dates[-1]["install_date"] if patches_with_dates else None
    days_since_last = (today - newest).days if newest else None

    recent = [p for p in patches if p["days_old"] is not None
              and p["days_old"] <= CE_PATCH_DEADLINE_DAYS]
    overdue = [p for p in patches if p["days_old"] is not None
               and p["days_old"] > CE_PATCH_DEADLINE_DAYS * 6]

    # CE-PM-2 compliance: last patch should be within 14 days
    # (shows system is actively being patched)
    ce_compliant = days_since_last is not None and days_since_last <= CE_PATCH_DEADLINE_DAYS

    summary_lines = [
        f"Total patches found: {len(patches)}",
        f"Most recent patch: {newest.strftime('%d %B %Y') if newest else 'Unknown'}",
        f"Days since last patch: {days_since_last if days_since_last is not None else 'Unknown'}",
        f"Oldest patch date: {oldest.strftime('%d %B %Y') if oldest else 'Unknown'}",
        f"Patches installed in last 14 days: {len(recent)}",
        f"Cyber Essentials CE-PM-2 compliance: {'PASS' if ce_compliant else 'FAIL'}",
    ]
    if not ce_compliant and days_since_last is not None:
        summary_lines.append(
            f"WARNING: Last patch was {days_since_last} days ago - "
            f"exceeds the 14-day Cyber Essentials requirement"
        )

    return {
        "patches":               patches,
        "total_patches":         len(patches),
        "recent_patches":        recent,
        "overdue_patches":       overdue,
        "oldest_patch":          oldest.strftime("%Y-%m-%d") if oldest else None,
        "newest_patch":          newest.strftime("%Y-%m-%d") if newest else None,
        "days_since_last_patch": days_since_last,
        "compliant":             ce_compliant,
        "summary":               "\n".join(summary_lines)
    }


def generate_sample_patch_csv(output_path):
    """
    Generate a sample patch CSV for testing.
    Simulates a Windows Server with mixed patch ages - some recent, some overdue.
    """
    today = datetime.now()

    rows = [
        {"HotFixID": "KB5040442", "Description": "Security Update",
         "InstalledOn": (today - timedelta(days=5)).strftime("%m/%d/%Y %I:%M:%S %p")},
        {"HotFixID": "KB5039212", "Description": "Security Update",
         "InstalledOn": (today - timedelta(days=19)).strftime("%m/%d/%Y %I:%M:%S %p")},
        {"HotFixID": "KB5036909", "Description": "Cumulative Update",
         "InstalledOn": (today - timedelta(days=47)).strftime("%m/%d/%Y %I:%M:%S %p")},
        {"HotFixID": "KB5034441", "Description": "Security Update",
         "InstalledOn": (today - timedelta(days=90)).strftime("%m/%d/%Y %I:%M:%S %p")},
        {"HotFixID": "KB5031539", "Description": "Security Update",
         "InstalledOn": (today - timedelta(days=180)).strftime("%m/%d/%Y %I:%M:%S %p")},
        {"HotFixID": "KB5028997", "Description": "Cumulative Update",
         "InstalledOn": (today - timedelta(days=270)).strftime("%m/%d/%Y %I:%M:%S %p")},
    ]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["HotFixID", "Description", "InstalledOn"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Sample patch CSV written to {output_path}")


if __name__ == "__main__":
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "patches.csv"
    )
    generate_sample_patch_csv(sample_path)
    results = parse_patch_csv(sample_path)
    print("\n--- PATCH PARSE RESULTS ---")
    print(results["summary"])
