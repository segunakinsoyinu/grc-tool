"""
database.py
GRC Compliance Assessment Tool - SQLite Database Setup
7005SCN Individual Research Project - Segun Akinsoyinu
Coventry University MSc Cyber Security

Creates and populates the SQLite database with:
- Controls from Cyber Essentials v3.1 (NCSC)
- Controls from GDPR Article 32
- Controls from ISO/IEC 27001:2022 Annex A (technological + key organisational)
- Questionnaire questions with control mappings
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "grc_controls.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    c = conn.cursor()

    # ------------------------------------------------------------------ schema
    c.executescript("""
        CREATE TABLE IF NOT EXISTS controls (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            framework   TEXT NOT NULL,
            control_id  TEXT NOT NULL UNIQUE,
            control_name TEXT NOT NULL,
            description TEXT NOT NULL,
            category    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS questions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            section       TEXT NOT NULL,
            question_text TEXT NOT NULL UNIQUE,
            question_type TEXT NOT NULL DEFAULT 'yes_no',
            help_text     TEXT
        );

        CREATE TABLE IF NOT EXISTS question_control_mapping (
            question_id INTEGER NOT NULL,
            control_id  TEXT NOT NULL,
            FOREIGN KEY (question_id) REFERENCES questions(id),
            FOREIGN KEY (control_id)  REFERENCES controls(control_id)
        );

        CREATE TABLE IF NOT EXISTS assessments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            org_name     TEXT NOT NULL,
            contact_name TEXT NOT NULL,
            sector       TEXT,
            staff_count  TEXT,
            timestamp    TEXT DEFAULT (datetime('now')),
            status       TEXT DEFAULT 'in_progress'
        );

        CREATE TABLE IF NOT EXISTS assessment_responses (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            question_id   INTEGER NOT NULL,
            response      TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id),
            FOREIGN KEY (question_id)   REFERENCES questions(id)
        );

        CREATE TABLE IF NOT EXISTS assessment_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id   INTEGER NOT NULL,
            control_id      TEXT NOT NULL,
            framework       TEXT NOT NULL,
            status          TEXT NOT NULL,
            gap_description TEXT,
            recommendation  TEXT,
            evidence_source TEXT DEFAULT 'questionnaire',
            FOREIGN KEY (assessment_id) REFERENCES assessments(id),
            FOREIGN KEY (control_id)    REFERENCES controls(control_id)
        );
    """)

    # --------------------------------------------------- Cyber Essentials v3.1
    ce_controls = [
        ("Cyber Essentials", "CE-FW-1",  "Firewall Coverage",
         "All devices connected to the internet must be protected by a firewall. "
         "This applies to boundary firewalls and host-based firewalls on individual devices.",
         "Firewalls"),
        ("Cyber Essentials", "CE-FW-2",  "Default Deny Inbound",
         "The default firewall rule must deny all inbound connections unless they have been "
         "explicitly permitted. Only necessary services should be accessible from the internet.",
         "Firewalls"),
        ("Cyber Essentials", "CE-FW-3",  "Firewall Rule Documentation",
         "Firewall rules must be documented, approved by an authorised individual, and reviewed "
         "at least annually to ensure they remain appropriate.",
         "Firewalls"),
        ("Cyber Essentials", "CE-FW-4",  "Block Unnecessary Services",
         "Unnecessary or insecure services (such as Telnet, FTP, or SMBv1) must be blocked "
         "at the firewall and disabled on devices.",
         "Firewalls"),
        ("Cyber Essentials", "CE-SC-1",  "Change Default Passwords",
         "All default passwords on network devices, servers, applications, and services must be "
         "changed to strong passwords before the device or service is deployed.",
         "Secure Configuration"),
        ("Cyber Essentials", "CE-SC-2",  "Disable Unnecessary Accounts",
         "Unnecessary user accounts, including guest accounts and default vendor accounts, must "
         "be disabled or removed from all devices and systems.",
         "Secure Configuration"),
        ("Cyber Essentials", "CE-SC-3",  "Disable Auto-run",
         "Auto-run and auto-play features must be disabled to prevent malware executing "
         "automatically from removable media or network drives.",
         "Secure Configuration"),
        ("Cyber Essentials", "CE-SC-4",  "Minimal Software Installation",
         "Only software, roles, and services that are necessary for business operations should "
         "be installed or enabled. Unnecessary features must be disabled.",
         "Secure Configuration"),
        ("Cyber Essentials", "CE-SC-5",  "Remove Unused Software",
         "Software that is no longer required must be removed from devices. "
         "Unused applications increase the attack surface unnecessarily.",
         "Secure Configuration"),
        ("Cyber Essentials", "CE-UAC-1", "Admin Account Separation",
         "Administrative accounts must only be used for administrative tasks. "
         "Day-to-day activities such as email and web browsing must be done using standard accounts.",
         "User Access Control"),
        ("Cyber Essentials", "CE-UAC-2", "Least Privilege",
         "Users must only be granted the minimum level of access rights and privileges "
         "required to perform their job role. Access must be reviewed regularly.",
         "User Access Control"),
        ("Cyber Essentials", "CE-UAC-3", "MFA for Cloud Services",
         "Multi-factor authentication must be enabled for all cloud services accessible "
         "from the internet, including email, file storage, and productivity tools.",
         "User Access Control"),
        ("Cyber Essentials", "CE-UAC-4", "MFA for Remote Access",
         "Multi-factor authentication must be used for all remote access connections "
         "to the organisation's network and systems.",
         "User Access Control"),
        ("Cyber Essentials", "CE-UAC-5", "Password Policy",
         "A password policy must be in place requiring a minimum of 8 characters for standard "
         "accounts and 12 characters for administrative accounts. Passwords must not be shared.",
         "User Access Control"),
        ("Cyber Essentials", "CE-MP-1",  "Malware Protection Installed",
         "Anti-malware software must be installed and active on all devices that may be "
         "exposed to malware, including servers and workstations.",
         "Malware Protection"),
        ("Cyber Essentials", "CE-MP-2",  "Malware Definitions Updated",
         "Anti-malware software must be configured to update its definitions automatically "
         "and must be kept up to date at all times.",
         "Malware Protection"),
        ("Cyber Essentials", "CE-MP-3",  "Regular Malware Scans",
         "Anti-malware scans must be performed regularly or in real time as files are accessed "
         "to detect and prevent malware infections.",
         "Malware Protection"),
        ("Cyber Essentials", "CE-MP-4",  "Block Malicious Execution",
         "Execution of malware from removable media, email attachments, and untrusted downloads "
         "must be prevented through technical controls.",
         "Malware Protection"),
        ("Cyber Essentials", "CE-PM-1",  "Licensed and Supported Software",
         "All software installed on devices must be licensed and supported by the vendor. "
         "End-of-life software must be removed or isolated from the network.",
         "Patch Management"),
        ("Cyber Essentials", "CE-PM-2",  "Patch Within 14 Days",
         "High and critical security patches and updates must be applied within 14 days of "
         "release. This applies to all software including operating systems and applications.",
         "Patch Management"),
        ("Cyber Essentials", "CE-PM-3",  "Remove Unsupported Software",
         "Applications and operating systems that are no longer supported by the vendor "
         "must be removed from devices or isolated from other network assets.",
         "Patch Management"),
        ("Cyber Essentials", "CE-PM-4",  "Auto-update Enabled",
         "Where possible, automatic updates should be enabled so that patches are applied "
         "promptly without requiring manual intervention.",
         "Patch Management"),
    ]

    # ---------------------------------------------------------- GDPR Article 32
    gdpr_controls = [
        ("GDPR Article 32", "GDPR-32-1",  "Pseudonymisation",
         "Personal data should be pseudonymised where appropriate as a technical measure "
         "to reduce risk when data is processed or stored.",
         "Technical Measures"),
        ("GDPR Article 32", "GDPR-32-2",  "Encryption of Personal Data",
         "Personal data must be encrypted both at rest and in transit using appropriate "
         "encryption standards (e.g. AES-256 for storage, TLS 1.2+ for transmission).",
         "Technical Measures"),
        ("GDPR Article 32", "GDPR-32-3",  "Confidentiality of Processing Systems",
         "Systems that process personal data must maintain ongoing confidentiality. "
         "Unauthorised access to personal data must be prevented.",
         "CIA Triad"),
        ("GDPR Article 32", "GDPR-32-4",  "Integrity of Processing Systems",
         "Systems that process personal data must maintain ongoing integrity. "
         "Data must not be altered or corrupted without authorisation.",
         "CIA Triad"),
        ("GDPR Article 32", "GDPR-32-5",  "Availability of Processing Systems",
         "Systems that process personal data must maintain ongoing availability. "
         "Data must be accessible to authorised users when needed.",
         "CIA Triad"),
        ("GDPR Article 32", "GDPR-32-6",  "Resilience of Processing Systems",
         "Systems processing personal data must be resilient. The organisation must be able "
         "to continue processing personal data in the event of a technical incident.",
         "CIA Triad"),
        ("GDPR Article 32", "GDPR-32-7",  "Data Recovery Capability",
         "The organisation must have the ability to restore availability and access to personal "
         "data in a timely manner following a physical or technical incident.",
         "Recovery"),
        ("GDPR Article 32", "GDPR-32-8",  "Regular Security Testing",
         "A process for regularly testing, assessing, and evaluating the effectiveness of "
         "technical and organisational security measures must be implemented.",
         "Testing"),
        ("GDPR Article 32", "GDPR-32-9",  "Access Controls for Personal Data",
         "Access to personal data must be restricted to authorised personnel only through "
         "appropriate technical access controls.",
         "Access Control"),
        ("GDPR Article 32", "GDPR-32-10", "Logging and Monitoring of Data Access",
         "Access to personal data must be logged and monitored. Logs must be retained "
         "for a sufficient period to support incident investigation.",
         "Monitoring"),
        ("GDPR Article 32", "GDPR-32-11", "Staff Data Protection Training",
         "Staff with access to personal data must receive appropriate training on data "
         "protection responsibilities and security measures.",
         "Organisational Measures"),
        ("GDPR Article 32", "GDPR-32-12", "Breach Response and Notification",
         "The organisation must have a documented procedure for detecting, responding to, "
         "and notifying personal data breaches within 72 hours to the ICO where required.",
         "Incident Response"),
    ]

    # -------------------------------- ISO 27001:2022 Annex A (selected controls)
    iso_controls = [
        ("ISO 27001:2022", "ISO-A.5.15", "Access Control Policy",
         "Rules to control physical and logical access to information and other associated "
         "assets must be established and implemented based on business and security requirements.",
         "Organisational Controls"),
        ("ISO 27001:2022", "ISO-A.5.16", "Identity Management",
         "The full lifecycle of identities must be managed. This includes creation, maintenance, "
         "and deletion of identities for users, devices, and services.",
         "Organisational Controls"),
        ("ISO 27001:2022", "ISO-A.5.17", "Authentication Information",
         "Allocation and management of authentication information must be controlled by a "
         "management process including advising personnel on appropriate handling.",
         "Organisational Controls"),
        ("ISO 27001:2022", "ISO-A.5.18", "Access Rights",
         "Access rights to information and associated assets must be provisioned, reviewed, "
         "modified, and removed in accordance with the access control policy.",
         "Organisational Controls"),
        ("ISO 27001:2022", "ISO-A.5.23", "Cloud Services Security",
         "Processes for acquisition, use, management, and exit from cloud services must be "
         "established in accordance with the organisation's information security requirements.",
         "Organisational Controls"),
        ("ISO 27001:2022", "ISO-A.8.1",  "User Endpoint Devices",
         "Information stored on, processed by, or accessible via user endpoint devices must "
         "be protected through appropriate policies and technical controls.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.2",  "Privileged Access Rights",
         "The allocation and use of privileged access rights must be restricted and managed. "
         "Privileged accounts must be monitored and reviewed regularly.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.3",  "Information Access Restriction",
         "Access to information and application system functions must be restricted in "
         "accordance with the established access control policy.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.5",  "Secure Authentication",
         "Secure authentication technologies and procedures must be implemented based on "
         "information access restrictions and the topic-specific policy on access control.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.7",  "Protection Against Malware",
         "Protection against malware must be implemented and supported by appropriate user "
         "awareness training.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.8",  "Management of Technical Vulnerabilities",
         "Information about technical vulnerabilities of information systems must be obtained, "
         "the exposure evaluated, and appropriate measures taken to address the associated risk.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.9",  "Configuration Management",
         "Configurations, including security configurations, of hardware, software, services, "
         "and networks must be established, documented, implemented, monitored, and reviewed.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.10", "Information Deletion",
         "Information stored in information systems, devices, or in any other storage media "
         "must be deleted when no longer required.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.13", "Information Backup",
         "Backup copies of information, software, and systems must be maintained and regularly "
         "tested in accordance with the agreed backup policy.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.14", "Redundancy of Processing Facilities",
         "Information processing facilities must be implemented with sufficient redundancy "
         "to meet availability requirements.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.15", "Logging",
         "Logs recording user activities, exceptions, faults, and information security events "
         "must be produced, stored, protected, and analysed.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.16", "Monitoring Activities",
         "Networks, systems, and applications must be monitored for anomalous behaviour. "
         "Appropriate action must be taken to evaluate potential information security incidents.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.17", "Clock Synchronisation",
         "The clocks of information processing systems must be synchronised to approved "
         "time sources and checked regularly.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.19", "Software Installation Controls",
         "Procedures and measures must be implemented to securely manage software installation "
         "on operational systems.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.20", "Network Security",
         "Networks and network devices must be secured, managed, and controlled to protect "
         "information systems and applications.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.21", "Security of Network Services",
         "Security mechanisms, service levels, and service requirements of all network services "
         "must be identified, implemented, and monitored.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.22", "Segregation of Networks",
         "Groups of information services, users, and information systems must be segregated "
         "in the organisation's networks.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.23", "Web Filtering",
         "Access to external websites must be managed to reduce exposure to malicious content. "
         "This includes blocking known malicious sites and inappropriate content.",
         "Technological Controls"),
        ("ISO 27001:2022", "ISO-A.8.24", "Use of Cryptography",
         "Rules for the effective use of cryptography, including cryptographic key management, "
         "must be defined and implemented.",
         "Technological Controls"),
    ]

    # Insert controls (skip duplicates)
    all_controls = ce_controls + gdpr_controls + iso_controls
    for ctrl in all_controls:
        c.execute("""
            INSERT OR IGNORE INTO controls
                (framework, control_id, control_name, description, category)
            VALUES (?, ?, ?, ?, ?)
        """, ctrl)

    # --------------------------------------------------- Questionnaire questions
    questions = [
        # --- Firewalls / Network
        ("Firewalls",
         "Do you use a firewall to protect all devices connected to the internet?",
         "yes_no",
         "This includes both a boundary firewall protecting your network perimeter and "
         "host-based firewalls on individual devices such as laptops and servers."),
        ("Firewalls",
         "Does your firewall block all inbound connections by default unless explicitly permitted?",
         "yes_no",
         "The default rule should deny everything. Only services you intentionally expose "
         "should have inbound rules."),
        ("Firewalls",
         "Are your firewall rules documented and reviewed at least once per year?",
         "yes_no",
         "Documentation should describe each rule, its purpose, and the person who approved it."),
        ("Firewalls",
         "Have you disabled or blocked unnecessary services such as Telnet, FTP, or SMBv1?",
         "yes_no",
         "Unused or insecure protocols should be blocked at the firewall and disabled on devices."),

        # --- Secure Configuration
        ("Secure Configuration",
         "Have you changed all default passwords on network devices, servers, and applications "
         "before deploying them?",
         "yes_no",
         "Default vendor passwords are publicly known and must be replaced with strong unique "
         "passwords before any device is used."),
        ("Secure Configuration",
         "Have you disabled or removed unnecessary user accounts including guest and vendor accounts?",
         "yes_no",
         "Accounts that are not needed for business operations should be removed to reduce "
         "the risk of unauthorised access."),
        ("Secure Configuration",
         "Is auto-run and auto-play disabled on all devices to prevent malware from executing "
         "automatically from removable media?",
         "yes_no",
         "Auto-run features can allow malware on USB drives or CDs to execute without user action."),
        ("Secure Configuration",
         "Do you remove or uninstall software that is no longer needed from devices?",
         "yes_no",
         "Unused software increases the attack surface and may contain unpatched vulnerabilities."),

        # --- User Access Control
        ("User Access Control",
         "Do administrative accounts have separate credentials and are they only used for "
         "administrative tasks?",
         "yes_no",
         "Admin accounts should not be used for everyday tasks like email. "
         "A separate standard account should be used for normal work."),
        ("User Access Control",
         "Are users only granted the minimum level of access rights required for their job role?",
         "yes_no",
         "This is the principle of least privilege. Access should be reviewed when roles change."),
        ("User Access Control",
         "Is multi-factor authentication (MFA) enabled for all cloud services such as email, "
         "file storage, and productivity tools?",
         "yes_no",
         "MFA adds a second verification step beyond a password and is required by "
         "Cyber Essentials v3.1 for all cloud services."),
        ("User Access Control",
         "Is multi-factor authentication (MFA) required for all remote access to your network?",
         "yes_no",
         "Remote access includes VPN, RDP, and any other method of connecting to company "
         "systems from outside the office."),
        ("User Access Control",
         "Do you have a written password policy requiring a minimum password length?",
         "yes_no",
         "Cyber Essentials requires minimum 8 characters for standard accounts and "
         "12 characters for administrative accounts."),

        # --- Malware Protection
        ("Malware Protection",
         "Is anti-malware software installed and active on all applicable devices including "
         "servers and workstations?",
         "yes_no",
         "Anti-malware must be active and running, not just installed."),
        ("Malware Protection",
         "Is anti-malware software configured to update its definitions automatically?",
         "yes_no",
         "Outdated definitions cannot detect recent malware. Automatic updates ensure "
         "the software stays current."),
        ("Malware Protection",
         "Are real-time or scheduled malware scans performed on all devices?",
         "yes_no",
         "Scans should run on file access (real-time) or on a regular schedule."),

        # --- Patch Management
        ("Patch Management",
         "Is all software on your systems licensed and still supported by the vendor?",
         "yes_no",
         "End-of-life software no longer receives security patches and must be removed "
         "or isolated from the network."),
        ("Patch Management",
         "Are high and critical security patches applied within 14 days of release?",
         "yes_no",
         "Cyber Essentials v3.1 requires all high and critical patches to be applied "
         "within 14 days of the vendor releasing them."),
        ("Patch Management",
         "Is automatic updating enabled where possible to ensure timely patch application?",
         "yes_no",
         "Automatic updates reduce the risk of patches being missed or delayed."),

        # --- GDPR Article 32
        ("GDPR Article 32",
         "Is personal data encrypted at rest on your systems and storage devices?",
         "yes_no",
         "Encryption at rest protects personal data if a device is physically stolen "
         "or storage media is accessed without authorisation."),
        ("GDPR Article 32",
         "Is personal data encrypted in transit when sent across networks or the internet?",
         "yes_no",
         "All transmission of personal data should use TLS 1.2 or higher. "
         "Unencrypted transmission exposes data to interception."),
        ("GDPR Article 32",
         "Are access controls in place that restrict who can view or process personal data?",
         "yes_no",
         "Only staff who need access to personal data for their job role should be able "
         "to access it."),
        ("GDPR Article 32",
         "Do you maintain logs of who accesses personal data and when?",
         "yes_no",
         "Access logs are required to detect unauthorised access and support breach "
         "investigation under GDPR Article 32."),
        ("GDPR Article 32",
         "Do you have tested backup and recovery procedures for systems containing personal data?",
         "yes_no",
         "Backups must be tested to confirm data can be restored. Untested backups "
         "may fail when needed."),
        ("GDPR Article 32",
         "Do you have a documented data breach response procedure including 72-hour notification?",
         "yes_no",
         "Under UK GDPR, personal data breaches must be reported to the ICO within 72 hours "
         "of becoming aware of them where the breach is likely to result in risk to individuals."),
        ("GDPR Article 32",
         "Do you apply pseudonymisation or anonymisation techniques to personal data where "
         "appropriate, such as for analytics, testing, or long-term storage?",
         "yes_no",
         "Pseudonymisation replaces identifying fields with pseudonyms to reduce risk. "
         "GDPR Article 32 specifically recommends it as a technical security measure."),

        # --- ISO 27001:2022
        ("ISO 27001:2022",
         "Do you have a documented information security policy approved by management?",
         "yes_no",
         "ISO 27001 requires a written policy defining the organisation's approach to "
         "information security."),
        ("ISO 27001:2022",
         "Do you maintain a register of all user accounts and review access rights regularly?",
         "yes_no",
         "Access rights must be reviewed when staff join, leave, or change roles."),
        ("ISO 27001:2022",
         "Is your network segmented to separate different groups such as guest WiFi, "
         "staff devices, and servers?",
         "yes_no",
         "Network segregation limits the spread of attacks and reduces the risk of "
         "unauthorised access between zones."),
        ("ISO 27001:2022",
         "Do you monitor your systems and network for unusual or suspicious activity?",
         "yes_no",
         "Monitoring should cover network traffic, failed login attempts, and unusual "
         "data transfers."),
        ("ISO 27001:2022",
         "Do you have a documented configuration baseline for all critical systems?",
         "yes_no",
         "A configuration baseline records the approved secure settings for each system "
         "and allows deviations to be detected."),
        ("ISO 27001:2022",
         "Do you perform vulnerability assessments or penetration tests at least annually?",
         "yes_no",
         "Regular testing identifies weaknesses before attackers can exploit them."),
        ("ISO 27001:2022",
         "Do you have redundancy or failover capability for critical business systems?",
         "yes_no",
         "Redundancy ensures availability of critical systems and supports business "
         "continuity during incidents."),
        ("ISO 27001:2022",
         "Do you have a documented and tested process for securely deleting data when it is "
         "no longer required?",
         "yes_no",
         "Data that is no longer needed should be securely deleted to prevent "
         "unauthorised recovery."),
    ]

    for q in questions:
        c.execute("""
            INSERT OR IGNORE INTO questions
                (section, question_text, question_type, help_text)
            VALUES (?, ?, ?, ?)
        """, q)

    conn.commit()

    # --------------------------------- question to control mappings
    # Fetch question IDs by text snippet
    def qid(snippet):
        row = c.execute(
            "SELECT id FROM questions WHERE question_text LIKE ?",
            (f"%{snippet}%",)
        ).fetchone()
        return row["id"] if row else None

    mappings = [
        # Q: firewall to protect all devices
        (qid("firewall to protect all devices"), ["CE-FW-1", "ISO-A.8.20"]),
        # Q: block all inbound connections by default
        (qid("block all inbound connections by default"), ["CE-FW-2", "CE-FW-3"]),
        # Q: firewall rules documented and reviewed
        (qid("firewall rules documented and reviewed"), ["CE-FW-3", "ISO-A.8.9"]),
        # Q: disabled or blocked unnecessary services
        (qid("disabled or blocked unnecessary services"), ["CE-FW-4", "CE-SC-4", "ISO-A.8.9"]),
        # Q: changed all default passwords
        (qid("changed all default passwords"), ["CE-SC-1", "ISO-A.8.5", "GDPR-32-3"]),
        # Q: disabled or removed unnecessary user accounts
        (qid("disabled or removed unnecessary user accounts"), ["CE-SC-2", "ISO-A.5.16"]),
        # Q: auto-run and auto-play disabled
        (qid("auto-run and auto-play disabled"), ["CE-SC-3", "CE-MP-4"]),
        # Q: remove or uninstall software that is no longer needed
        (qid("remove or uninstall software"), ["CE-SC-5", "ISO-A.8.10"]),
        # Q: administrative accounts have separate credentials
        (qid("administrative accounts have separate credentials"), ["CE-UAC-1", "ISO-A.8.2"]),
        # Q: minimum level of access rights required for their job role
        (qid("minimum level of access rights"), ["CE-UAC-2", "ISO-A.5.18", "GDPR-32-9"]),
        # Q: MFA for cloud services
        (qid("MFA) enabled for all cloud services"), ["CE-UAC-3", "ISO-A.8.5", "ISO-A.5.23"]),
        # Q: MFA for remote access
        (qid("MFA) required for all remote access"), ["CE-UAC-4", "ISO-A.8.5"]),
        # Q: written password policy
        (qid("written password policy"), ["CE-UAC-5", "ISO-A.5.17", "GDPR-32-9"]),
        # Q: anti-malware installed and active
        (qid("anti-malware software installed and active"), ["CE-MP-1", "ISO-A.8.7"]),
        # Q: anti-malware update definitions automatically
        (qid("update its definitions automatically"), ["CE-MP-2", "ISO-A.8.7"]),
        # Q: real-time or scheduled malware scans
        (qid("real-time or scheduled malware scans"), ["CE-MP-3", "ISO-A.8.7"]),
        # Q: licensed and still supported
        (qid("licensed and still supported"), ["CE-PM-1", "ISO-A.8.8"]),
        # Q: patches applied within 14 days
        (qid("patches applied within 14 days"), ["CE-PM-2", "ISO-A.8.8", "GDPR-32-8"]),
        # Q: automatic updating enabled
        (qid("automatic updating enabled"), ["CE-PM-4", "ISO-A.8.19"]),
        # Q: personal data encrypted at rest
        (qid("personal data encrypted at rest"), ["GDPR-32-2", "ISO-A.8.24"]),
        # Q: personal data encrypted in transit
        (qid("personal data encrypted in transit"), ["GDPR-32-2", "ISO-A.8.24"]),
        # Q: access controls in place that restrict who can view
        (qid("access controls in place that restrict who can view"), ["GDPR-32-9", "ISO-A.8.3", "CE-UAC-2"]),
        # Q: logs of who accesses personal data
        (qid("logs of who accesses personal data"), ["GDPR-32-10", "ISO-A.8.15"]),
        # Q: tested backup and recovery procedures
        (qid("tested backup and recovery procedures"), ["GDPR-32-7", "ISO-A.8.13"]),
        # Q: documented data breach response procedure
        (qid("documented data breach response procedure"), ["GDPR-32-12"]),
        # Q: documented information security policy
        (qid("documented information security policy"), ["ISO-A.5.15"]),
        # Q: register of all user accounts
        (qid("register of all user accounts"), ["ISO-A.5.16", "ISO-A.5.18", "CE-UAC-2"]),
        # Q: network segmented to separate different groups
        (qid("network segmented to separate different groups"), ["ISO-A.8.22", "CE-FW-1"]),
        # Q: monitor your systems and network for unusual
        (qid("monitor your systems and network"), ["ISO-A.8.16", "GDPR-32-10"]),
        # Q: documented configuration baseline
        (qid("documented configuration baseline"), ["ISO-A.8.9", "CE-SC-1"]),
        # Q: vulnerability assessments or penetration tests
        (qid("vulnerability assessments or penetration tests"), ["ISO-A.8.8", "GDPR-32-8"]),
        # Q: redundancy or failover capability
        (qid("redundancy or failover capability"), ["ISO-A.8.14", "GDPR-32-6", "GDPR-32-5"]),
        # Q: securely deleting data
        (qid("securely deleting data"), ["ISO-A.8.10"]),
        (qid("pseudonymisation or anonymisation techniques"), ["GDPR-32-1"]),
    ]

    # question_control_mapping was created without a UNIQUE constraint, so the
    # INSERT OR IGNORE below had nothing to violate and never ignored anything.
    # Every init_db() call, meaning every server start, appended another complete
    # copy of the mapping set. get_controls_for_question() JOINs this table, so
    # each duplicate multiplied the number of controls sent to the model in a
    # single prompt, and the model began omitting controls from its response.
    # The mapping list above is the single source of truth, so it is safe to
    # rebuild the table from it on every start. The unique index then makes the
    # INSERT OR IGNORE behave as originally intended.
    c.execute("DELETE FROM question_control_mapping")
    c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_qcm_unique
            ON question_control_mapping (question_id, control_id)
    """)

    for question_id, control_ids in mappings:
        if question_id is None:
            continue
        for ctrl_id in control_ids:
            c.execute("""
                INSERT OR IGNORE INTO question_control_mapping
                    (question_id, control_id)
                VALUES (?, ?)
            """, (question_id, ctrl_id))

    # Retroactive fix: remove incorrect mapping of GDPR-32-1 to the data
    # deletion question. GDPR-32-1 is Pseudonymisation, not data deletion.
    c.execute("""
        DELETE FROM question_control_mapping
        WHERE control_id = 'GDPR-32-1'
        AND question_id = (
            SELECT id FROM questions WHERE question_text LIKE '%securely deleting data%'
        )
    """)

    # Retroactive fix: insert missing MFA question mappings.
    # The original qid() snippets used "MFA enabled" and "MFA required" but the
    # actual question text contains "(MFA) enabled" and "(MFA) required". The
    # closing parenthesis prevented LIKE matching so qid() returned None and
    # these mappings were never inserted, leaving CE-UAC-3, CE-UAC-4, and
    # ISO-A.5.23 unassessed in all prior assessments.
    mfa_cloud = c.execute(
        "SELECT id FROM questions WHERE question_text LIKE '%MFA) enabled for all cloud services%'"
    ).fetchone()
    mfa_remote = c.execute(
        "SELECT id FROM questions WHERE question_text LIKE '%MFA) required for all remote access%'"
    ).fetchone()
    for ctrl_id in ["CE-UAC-3", "ISO-A.8.5", "ISO-A.5.23"]:
        if mfa_cloud and not c.execute(
            "SELECT 1 FROM question_control_mapping WHERE question_id = ? AND control_id = ?",
            (mfa_cloud["id"], ctrl_id)
        ).fetchone():
            c.execute(
                "INSERT INTO question_control_mapping (question_id, control_id) VALUES (?, ?)",
                (mfa_cloud["id"], ctrl_id)
            )
    for ctrl_id in ["CE-UAC-4", "ISO-A.8.5"]:
        if mfa_remote and not c.execute(
            "SELECT 1 FROM question_control_mapping WHERE question_id = ? AND control_id = ?",
            (mfa_remote["id"], ctrl_id)
        ).fetchone():
            c.execute(
                "INSERT INTO question_control_mapping (question_id, control_id) VALUES (?, ?)",
                (mfa_remote["id"], ctrl_id)
            )

    conn.commit()
    conn.close()
    print(f"Database initialised at {DB_PATH}")
    print(f"Controls loaded: {len(all_controls)}")
    print(f"Questions loaded: {len(questions)}")


def get_questions():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM questions ORDER BY section, id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_controls_for_question(question_id):
    conn = get_connection()
    rows = conn.execute("""
        SELECT c.*
        FROM controls c
        JOIN question_control_mapping qcm ON c.control_id = qcm.control_id
        WHERE qcm.question_id = ?
    """, (question_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_controls():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM controls ORDER BY framework, control_id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_assessment(org_name, contact_name, sector, staff_count):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO assessments (org_name, contact_name, sector, staff_count)
        VALUES (?, ?, ?, ?)
    """, (org_name, contact_name, sector, staff_count))
    assessment_id = c.lastrowid
    conn.commit()
    conn.close()
    return assessment_id


def save_response(assessment_id, question_id, response):
    conn = get_connection()
    conn.execute("""
        INSERT INTO assessment_responses (assessment_id, question_id, response)
        VALUES (?, ?, ?)
    """, (assessment_id, question_id, response))
    conn.commit()
    conn.close()


def save_finding(assessment_id, control_id, framework, status,
                 gap_description, recommendation, evidence_source="questionnaire"):
    conn = get_connection()
    conn.execute("""
        INSERT INTO assessment_findings
            (assessment_id, control_id, framework, status,
             gap_description, recommendation, evidence_source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (assessment_id, control_id, framework, status,
          gap_description, recommendation, evidence_source))
    conn.commit()
    conn.close()


def get_saved_control_ids(assessment_id):
    """
    Return the set of control IDs already saved for this assessment.
    Used by run_full_assessment() to skip controls already assessed by
    assess_nmap_findings(), ensuring technical evidence takes precedence
    over self-reported questionnaire answers and preventing duplicate rows.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT control_id FROM assessment_findings WHERE assessment_id = ?",
        (assessment_id,)
    ).fetchall()
    conn.close()
    return {row["control_id"] for row in rows}


def get_all_control_ids():
    """Return the set of every control_id defined in the controls table.

    Used to reject AI findings whose control_id does not exist. Foreign keys are
    not enforced, so save_finding() will write any string; the inner JOIN in
    get_findings() then hides the row from reports while it still counts in any
    query against the database. Assessments 10 and 13 each contain one such row,
    where the model returned the framework name in the control_id field.
    """
    conn = get_connection()
    rows = conn.execute("SELECT control_id FROM controls").fetchall()
    conn.close()
    return {row["control_id"] for row in rows}


def get_mapped_control_ids():
    """Return the set of control IDs reachable through the questionnaire.

    This is the 51 of 58 controls the assessment instrument can evaluate; the
    other seven require documentation review or physical inspection.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT DISTINCT control_id FROM question_control_mapping"
    ).fetchall()
    conn.close()
    return {row["control_id"] for row in rows}


def get_findings(assessment_id):
    conn = get_connection()
    rows = conn.execute("""
        SELECT f.*, c.control_name, c.category
        FROM assessment_findings f
        JOIN controls c ON f.control_id = c.control_id
        WHERE f.assessment_id = ?
        ORDER BY f.framework, f.control_id
    """, (assessment_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_assessment(assessment_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def complete_assessment(assessment_id):
    conn = get_connection()
    conn.execute(
        "UPDATE assessments SET status = 'complete' WHERE id = ?",
        (assessment_id,)
    )
    conn.commit()
    conn.close()


def set_assessment_status(assessment_id, status):
    """Set an arbitrary status on an assessment (e.g. 'awaiting_evidence')."""
    conn = get_connection()
    conn.execute(
        "UPDATE assessments SET status = ? WHERE id = ?",
        (status, assessment_id)
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
