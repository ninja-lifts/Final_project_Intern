#!/usr/bin/env python3
import os
import subprocess
import socket
import datetime

def run(cmd):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

# ----------------------
# CIS-Aware Checks
# ----------------------

def check_firewall_cis():
    """CIS 3.5 - Default INPUT policy must be DROP or REJECT"""
    rules = run(['iptables', '-L', '-n', '-v'])
    if not rules:
        return 0, "iptables not active (CIS FAIL)"

    # CIS expects default DROP or REJECT
    if "Chain INPUT (policy DROP" in rules or "Chain INPUT (policy REJECT" in rules:
        # Check for overly permissive rule
        if "ACCEPT     all  --  0.0.0.0/0" in rules:
            return 0, "Permissive rule found (CIS FAIL)"
        return 25, "Firewall policy matches CIS (DROP/REJECT)"
    return 0, "Default policy not DROP/REJECT (CIS FAIL)"

def check_services_cis():
    """CIS 2.2 - Minimize services (score proportional to CIS compliance)."""
    services = run(['systemctl', 'list-units', '--type=service', '--state=running'])
    lines = [line for line in services.split('\n') if '.service' in line]
    whitelist = ['ssh', 'systemd-journald', 'systemd-logind', 'cron', 'dbus']
    flagged = [line for line in lines if not any(w in line for w in whitelist)]

    # CIS wants minimal unnecessary services
    percent_ok = max(0, 100 - int(len(flagged) * 100 / max(1, len(lines))))
    points = int(30 * percent_ok / 100)
    return points, f"{percent_ok}% services compliant with CIS"

def check_ssh_cis():
    """CIS 5.2 - PermitRootLogin=no and no weak KEX algorithms."""
    sshd_config = run(['sudo', 'sshd', '-T']).lower()
    # CIS requires PermitRootLogin=no and no weak KEX
    if "permitrootlogin yes" in sshd_config:
        return 0, "CIS FAIL: PermitRootLogin allowed"
    if "kexalgorithms +diffie-hellman-group1-sha1" in sshd_config:
        return 0, "CIS FAIL: Weak KEX enabled"
    return 25, "SSH configuration meets CIS"

def check_rootkit():
    """Not CIS, but keep as hygiene check (20 points max)."""
    warnings = []
    if os.path.exists('/usr/bin/rkhunter'):
        output = run(['rkhunter', '--check', '--sk', '--rwo']).lower()
        if "rootkit" in output and "found" in output:
            return 0, "Rootkit FOUND - Critical", [output]
        if "warning" in output:
            warnings = [line for line in output.split('\n') if "warning" in line]
            return 10, "Warnings found (review needed)", warnings
        if "0 suspect files" in output or "no suspect files" in output:
            return 20, "No rootkit indicators", []
        return 0, "Suspicious files found", [output]
    return 0, "rkhunter not installed", []

# ----------------------
# Main Execution
# ----------------------

def main():
    hostname = socket.gethostname()
    date = datetime.datetime.now().strftime('%Y-%m-%d')

    # CIS-driven checks
    fw_pts, fw_msg = check_firewall_cis()
    svc_pts, svc_msg = check_services_cis()
    ssh_pts, ssh_msg = check_ssh_cis()
    rootkit_pts, rootkit_msg, rootkit_warnings = check_rootkit()

    # Total score (rootkit isn't CIS but included)
    score = fw_pts + svc_pts + ssh_pts + rootkit_pts

    print("==== Linux Hardening Audit (CIS-Aligned) ====")
    print(f"Hostname        : {hostname}")
    print(f"Date            : {date}")
    print("------------------------------------------------")
    print(f"Section                 Status                        Points")
    print(f"Firewall Rules          {fw_msg:<35} {fw_pts}/25")
    print(f"Service Exposure        {svc_msg:<35} {svc_pts}/30")
    print(f"SSH Configuration       {ssh_msg:<35} {ssh_pts}/25")
    print(f"Rootkit Indicators      {rootkit_msg:<35} {rootkit_pts}/20")
    print("------------------------------------------------")
    print(f"TOTAL HARDENING SCORE (CIS)     {score}/100")
    print("------------------------------------------------")
    print("Priority Fixes")
    idx = 1
    if fw_pts < 25:
        print(f"[{idx}] Align firewall with CIS (set default DROP/REJECT)"); idx += 1
    if svc_pts < 30:
        print(f"[{idx}] Disable unnecessary services (see report)"); idx += 1
    if ssh_pts < 25:
        print(f"[{idx}] Harden SSH per CIS (disable root login, weak KEX)"); idx += 1
    if rootkit_pts < 20:
        print(f"[{idx}] Investigate rkhunter warnings/rootkit alerts (see report)"); idx += 1
    print(f"Detailed findings saved to ./hardening-report-{date}.txt")

    # Save detailed report
    report_filename = f"./hardening-report-{date}.txt"
    with open(report_filename, "w") as f:
        f.write("Firewall Check:\n" + fw_msg + "\n")
        f.write("Services Check:\n" + svc_msg + "\n")
        f.write("SSH Check:\n" + ssh_msg + "\n")
        f.write("Rootkit Check:\n" + rootkit_msg + "\n")
        if rootkit_warnings:
            f.write("\nRootkit Warnings:\n")
            for line in rootkit_warnings:
                f.write(line + "\n")

if __name__ == '__main__':
    main()
