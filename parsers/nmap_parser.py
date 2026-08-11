"""
parsers/nmap_parser.py
GRC Compliance Assessment Tool - Nmap XML Parser
7005SCN Individual Research Project - Segun Akinsoyinu
Coventry University MSc Cyber Security

Parses Nmap XML scan output to extract:
- Open ports and services
- Operating system information
- Potentially dangerous or insecure services
- Evidence relevant to Cyber Essentials and ISO 27001 controls
"""

import xml.etree.ElementTree as ET
import os

# Services considered insecure or unnecessary per Cyber Essentials v3.1
DANGEROUS_SERVICES = {
    "telnet":   "Telnet (port 23) transmits data in plaintext including credentials",
    "ftp":      "FTP (port 21) transmits data and credentials in plaintext",
    "rsh":      "RSH is an insecure remote shell protocol with no encryption",
    "rlogin":   "Rlogin is an insecure remote login protocol",
    "rexec":    "Rexec is an insecure remote execution protocol",
    "tftp":     "TFTP has no authentication and should not be exposed",
    "snmp":     "SNMP v1/v2 uses community strings sent in plaintext",
    "http":     "Unencrypted HTTP exposes web traffic - HTTPS should be used instead",
    "smb":      "SMB exposure should be reviewed - SMBv1 is critically insecure",
    "msrpc":    "MS-RPC should not be exposed directly to the internet",
    "netbios":  "NetBIOS should not be exposed to the internet",
    "finger":   "Finger protocol exposes user information",
    "chargen":  "Chargen can be abused in amplification attacks",
    "echo":     "Echo protocol can be abused in amplification attacks",
    "daytime":  "Daytime protocol is unnecessary and should be disabled",
    "discard":  "Discard protocol is unnecessary and should be disabled",
}

# Port numbers associated with insecure services
DANGEROUS_PORTS = {
    21:   "FTP - plaintext file transfer",
    23:   "Telnet - plaintext remote access",
    25:   "SMTP - may indicate open mail relay if not expected",
    69:   "TFTP - unauthenticated file transfer",
    79:   "Finger - user information disclosure",
    111:  "RPC portmapper",
    135:  "MS-RPC",
    137:  "NetBIOS Name Service",
    138:  "NetBIOS Datagram Service",
    139:  "NetBIOS Session Service",
    161:  "SNMP - check version (v1/v2 are insecure)",
    445:  "SMB - check for SMBv1",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh/syslog",
    3389: "RDP - Remote Desktop Protocol (should be MFA-protected)",
    5900: "VNC - remote desktop (check if password-protected)",
    8080: "HTTP alternate - check if HTTPS redirect is configured",
    8443: "HTTPS alternate",
}

# Minimum Nmap OS-detection accuracy before an end-of-life match is treated as a
# finding. Nmap reports several osmatch candidates per host with an accuracy
# percentage each, and on a host it cannot fingerprint exactly it will list many
# low-confidence guesses covering a wide range of Windows versions. Without a
# threshold every one of those guesses was recorded as a confirmed end-of-life
# operating system, the accuracy figure was discarded, and the AI was handed the
# result as established fact. In one archived scan this produced assertions of
# Windows Vista, 7, 8/8.1, Server 2008 R2 and Server 2012 on a lab containing only
# Windows Server 2022 and Windows 10, and the claim then propagated into findings
# for CE-PM-1, GDPR-32-5 and ISO-A.8.14.
EOL_MIN_ACCURACY = 95

# Known end-of-life operating systems
EOL_OS_INDICATORS = [
    "windows xp", "windows vista", "windows 7", "windows 8",
    "windows server 2003", "windows server 2008",
    "ubuntu 14", "ubuntu 16", "ubuntu 18",
    "centos 6", "centos 7", "centos 8",
    "debian 8", "debian 9",
    "red hat enterprise linux 5", "red hat enterprise linux 6",
]


def parse_nmap_xml(xml_path):
    """
    Parse an Nmap XML file and extract compliance-relevant information.

    Args:
        xml_path: Path to the Nmap XML output file

    Returns:
        Dict with keys:
            hosts: list of host dicts
            open_ports: list of all open port numbers
            services: list of service name strings
            dangerous_services: list of dicts describing insecure findings
            os_info: list of detected OS strings
            eol_os_detected: list of end-of-life OS strings found
            summary: human-readable summary string
    """
    if not os.path.exists(xml_path):
        return {
            "error": f"Nmap file not found at {xml_path}",
            "hosts": [], "open_ports": [], "services": [],
            "dangerous_services": [], "os_info": [],
            "eol_os_detected": [], "summary": "No scan data available"
        }

    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts = []
    all_open_ports = []
    all_services = []
    dangerous_findings = []
    all_os_info = []
    eol_os = []

    for host in root.findall("host"):
        host_data = {
            "ip": None,
            "hostname": None,
            "status": None,
            "open_ports": [],
            "services": [],
            "os": []
        }

        # IP address
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host_data["ip"] = addr.get("addr")

        # Hostname
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                host_data["hostname"] = hn.get("name")
                break

        # Status
        status_el = host.find("status")
        if status_el is not None:
            host_data["status"] = status_el.get("state")

        # Ports
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num  = int(port.get("portid", 0))
                protocol  = port.get("protocol", "tcp")
                service_el = port.find("service")
                service_name   = service_el.get("name", "unknown") if service_el is not None else "unknown"
                service_product = service_el.get("product", "") if service_el is not None else ""
                service_version = service_el.get("version", "") if service_el is not None else ""

                port_info = {
                    "port":     port_num,
                    "protocol": protocol,
                    "service":  service_name,
                    "product":  service_product,
                    "version":  service_version
                }

                host_data["open_ports"].append(port_info)
                all_open_ports.append(port_num)

                service_str = f"{service_name}/{port_num}"
                if service_product:
                    service_str += f" ({service_product} {service_version})".strip()
                all_services.append(service_str)
                host_data["services"].append(service_str)

                # Check for dangerous services
                for dangerous_key, reason in DANGEROUS_SERVICES.items():
                    if dangerous_key in service_name.lower():
                        dangerous_findings.append({
                            "host":    host_data["ip"],
                            "port":    port_num,
                            "service": service_name,
                            "reason":  reason,
                            "severity": "high" if dangerous_key in
                                        ("telnet", "ftp", "rsh", "rlogin") else "medium"
                        })

                # Deduplication must be per host, not global. all_open_ports accumulates
                # across every host in the scan, so testing against it suppressed a port
                # that had already been seen on an earlier host: in a two-host scan the
                # workstation's port 445 was dropped because the server also exposed 445.
                # The check below is the correct one, scoped to this host's IP.
                if port_num in DANGEROUS_PORTS:
                    if not any(d["port"] == port_num and d["host"] == host_data["ip"]
                               for d in dangerous_findings):
                        dangerous_findings.append({
                            "host":    host_data["ip"],
                            "port":    port_num,
                            "service": service_name,
                            "reason":  DANGEROUS_PORTS[port_num],
                            "severity": "high" if port_num in (21, 23, 513, 514) else "medium"
                        })

        # OS detection
        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                os_name = osmatch.get("name", "")
                accuracy = osmatch.get("accuracy", "")
                if os_name:
                    os_str = f"{os_name} (accuracy: {accuracy}%)"
                    host_data["os"].append(os_str)
                    all_os_info.append(os_str)

                    try:
                        accuracy_pct = int(accuracy)
                    except (TypeError, ValueError):
                        accuracy_pct = 0

                    if accuracy_pct >= EOL_MIN_ACCURACY:
                        for eol in EOL_OS_INDICATORS:
                            if eol in os_name.lower():
                                eol_os.append({
                                    "host":     host_data["ip"],
                                    "os":       os_name,
                                    "accuracy": accuracy_pct,
                                    # The accuracy is carried into the note so the AI
                                    # receives the confidence alongside the claim and
                                    # cannot present a fingerprint guess as a fact.
                                    "note": (f"Nmap OS fingerprint matched an end-of-life "
                                             f"system at {accuracy_pct}% confidence. This is "
                                             f"a probabilistic match, not a confirmed "
                                             f"operating system version.")
                                })
                                break

        hosts.append(host_data)

    # Build human-readable summary
    summary_lines = []
    summary_lines.append(f"Hosts scanned: {len(hosts)}")
    summary_lines.append(f"Total open ports: {len(set(all_open_ports))}")
    if all_services:
        summary_lines.append(f"Services detected: {', '.join(set(all_services[:10]))}")
        # Service banner strings are reported verbatim above because they are genuine
        # scan output and suppressing them would be withholding evidence. They are
        # annotated instead. Nmap's SMB product string reports the range of Windows
        # releases that implement the observed SMB dialect (for example "Microsoft
        # Windows Server 2008 R2 - 2012"), not the operating system of the host. Left
        # unlabelled, the model read those ranges as OS detections and reported
        # Windows 7 and Server 2008 R2 as present on a lab running Server 2022 and
        # Windows 10. This is a second, independent propagation path to the same
        # false end-of-life claim that EOL_MIN_ACCURACY closed for osmatch entries.
        if any(k in s.lower() for s in all_services
               for k in ("microsoft-ds", "netbios", "smb")):
            summary_lines.append(
                "NOTE ON SERVICE BANNERS: SMB and NetBIOS product strings describe the "
                "range of Windows releases compatible with the observed protocol "
                "dialect. They are NOT the operating system of the host and must not "
                "be used to determine OS version or end-of-life status. Use the OS "
                "fingerprint section for that."
            )
    if dangerous_findings:
        summary_lines.append(
            f"INSECURE SERVICES DETECTED ({len(dangerous_findings)}): " +
            ", ".join(set(d['service'] + '/' + str(d['port'])
                         for d in dangerous_findings))
        )
    if eol_os:
        # Hedged deliberately. The previous wording ("END-OF-LIFE OS DETECTED")
        # asserted a fingerprint guess as an observed fact, and the AI reproduced
        # that assertion verbatim in its findings.
        summary_lines.append(
            "POSSIBLE END-OF-LIFE OS (Nmap fingerprint, not confirmed): " +
            ", ".join(f"{e['os']} at {e['accuracy']}% confidence" for e in eol_os)
        )

    return {
        "hosts":              hosts,
        "open_ports":         list(set(all_open_ports)),
        "services":           list(set(all_services)),
        "dangerous_services": dangerous_findings,
        "os_info":            all_os_info,
        "eol_os_detected":    eol_os,
        "summary":            "\n".join(summary_lines)
    }


def generate_sample_nmap_xml(output_path, target_ips=None):
    """
    Generate a sample Nmap XML file for testing when real scan is not yet available.
    Simulates a misconfigured SME server with deliberate vulnerabilities.
    """
    if target_ips is None:
        target_ips = ["10.0.2.20", "10.0.2.30"]

    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -oX nmap-scan.xml 10.0.2.20 10.0.2.30"
         start="1751500000" version="7.94" xmloutputversion="1.05">

  <host starttime="1751500001" endtime="1751500060">
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.2.20" addrtype="ipv4"/>
    <hostnames>
      <hostname name="windows-server-2022" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="Microsoft ftpd" version="7.5"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" product="Microsoft Windows XP telnetd"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Microsoft IIS" version="10.0"/>
      </port>
      <port protocol="tcp" portid="135">
        <state state="open" reason="syn-ack"/>
        <service name="msrpc" product="Microsoft Windows RPC"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="open" reason="syn-ack"/>
        <service name="netbios-ssn" product="Microsoft Windows netbios-ssn"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Windows Server 2022 microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
      </port>
    </ports>
    <os>
      <osmatch name="Microsoft Windows Server 2022" accuracy="96"/>
    </os>
  </host>

  <host starttime="1751500061" endtime="1751500120">
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.2.30" addrtype="ipv4"/>
    <hostnames>
      <hostname name="windows-10-workstation" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="135">
        <state state="open" reason="syn-ack"/>
        <service name="msrpc" product="Microsoft Windows RPC"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="open" reason="syn-ack"/>
        <service name="netbios-ssn" product="Microsoft Windows netbios-ssn"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Windows 10 microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="5900">
        <state state="open" reason="syn-ack"/>
        <service name="vnc" product="RealVNC 4.0"/>
      </port>
    </ports>
    <os>
      <osmatch name="Microsoft Windows 10" accuracy="94"/>
    </os>
  </host>

</nmaprun>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(xml_content)
    print(f"Sample Nmap XML written to {output_path}")


if __name__ == "__main__":
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "nmap-scan.xml"
    )
    generate_sample_nmap_xml(sample_path)
    results = parse_nmap_xml(sample_path)
    print("\n--- NMAP PARSE RESULTS ---")
    print(results["summary"])
    print(f"\nDangerous services found: {len(results['dangerous_services'])}")
    for d in results["dangerous_services"]:
        print(f"  [{d['severity'].upper()}] {d['host']}:{d['port']} - {d['service']} - {d['reason']}")
