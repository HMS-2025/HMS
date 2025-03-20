import yaml
import os
from GenerationRapport.GenerationRapport import generate_html_report

# --- Helper functions remain unchanged ---
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error loading  {file_path} : {e}")
        return {}

def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = []

    if rule_id == 'R71':
        detected = detected_values or {}
        issues = []
        if not detected.get("syslog_installed") == "Installed":
            issues.append(f"Syslog: '{detected.get('syslog_installed')}' (expected 'Installed')")
        if not detected.get("syslog_running") == "Running":
            issues.append(f"Syslog service: '{detected.get('syslog_running')}' (expected 'Running')")
        if not detected["auth_logs_configured"]:
            issues.append("Missing authentication logging configuration")
        if not detected["sys_events_configured"]:
            issues.append("System event logging configuration missing")
        for logfile, expected_perm in expected_values["log_files_permissions"].items():
            detected_perm = detected["log_files_permissions"].get(logfile, "Not Found")
            if detected_perm != expected_perm:
                issues.append(f"{logfile}: permissions '{detected_perm}' (expected '{expected_perm}')")
        if detected["log_forwarding_secure"] != expected_values["log_forwarding_secure"]:
            issues.append(f"Log forwarding security: '{detected['log_forwarding_secure']}' (expected '{expected_values['log_forwarding_secure']}')")
        return {
            "apply": not bool(issues),
            "status": "Compliant" if not issues else "Non-Compliant",
            "expected_elements": expected_values,
            "detected_elements": detected,
            "issues": issues or None
        }
    elif rule_id == "R72":
        issues = []
        for logfile, expected in reference_data.get("R72", {}).get("expected", {}).items():
            detected = detected_values.get(logfile, {})
            if detected.get("owner") != expected["owner"]:
                issues.append(f"{logfile} incorrect owner: detected '{detected.get('owner', 'None')}', expected '{expected['owner']}'")
            if detected.get("group") != expected["group"]:
                issues.append(f"{logfile}: detected group '{detected.get('group')}', expected '{expected['group']}'")
            if detected.get("permissions") != expected["permissions"]:
                issues.append(f"{logfile}: permissions '{detected.get('permissions')}' (expected '{expected['permissions']}')")
        return {
            "apply": not issues,
            "status": "Compliant" if not issues else "Non-Compliant",
            "expected_elements": reference_data["R72"]["expected"],
            "detected_elements": detected_values,
            "issues": issues or None
        }
    
    if isinstance(expected_values, dict):
        for key, value in expected_values.items():
            if isinstance(value, list):
                expected_values_list.extend(value)
            else:
                expected_values_list.append(value)
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    
    status = "Compliant" if detected_values == "active" else "Non-compliant"
    if detected_values == "Not Installed":
        status = "Not Installed"
    elif detected_values == "inactive":
        status = "Installed but Inactive"
    
    return {
        "apply": set(detected_values) == set(expected_values),
        "status": "Compliant" if set(detected_values) == set(expected_values) else "Non-Compliant",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }

def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "a", encoding="utf-8") as file:
        file.write("logging:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False)
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
    print(f"Report generated: {output_path}")

# --- Adapted functions for logging/auditing analysis ---
# Each function now accepts an extra parameter os_info and branches based on OS.
def get_audit_log_status(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        result = execute_ssh_command(serveur, "systemctl is-active auditd")
        if not result:
            return "Not Installed"
        if "inactive" in result:
            return "inactive"
        if "active" in result:
            return "active"
        return "Unknown"
    else:
        print(f"[get_audit_log_status] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); returning 'Unknown'.")
        return "Unknown"

def get_log_rotation(serveur, os_info):
    if get_audit_log_status(serveur, os_info) != "Not Installed":
        return execute_ssh_command(serveur, "cat /etc/logrotate.conf | grep rotate")
    else:
        return None

def get_auditd_configuration(serveur, os_info):
    if get_audit_log_status(serveur, os_info) != "Not Installed":
        return execute_ssh_command(serveur, "auditctl -l")
    else:
        return None

def get_admin_command_logging(serveur, os_info):
    if get_audit_log_status(serveur, os_info) != "Not Installed":
        return execute_ssh_command(serveur, "grep -E 'execve' /etc/audit/audit.rules")
    else:
        return None

def get_audit_log_protection(serveur, os_info):
    if get_audit_log_status(serveur, os_info) != "Not Installed":
        return execute_ssh_command(serveur, "ls -l /var/log/audit/")
    else:
        return None

def check_r33(serveur, os_info):
    audit_status = get_audit_log_status(serveur, os_info)
    return {
        "audit_log_status": audit_status,
        "auditd_configuration": get_auditd_configuration(serveur, os_info) if audit_status != "Not Installed" else None,
        "admin_command_logging": get_admin_command_logging(serveur, os_info) if audit_status != "Not Installed" else None,
        "audit_log_protection": get_audit_log_protection(serveur, os_info) if audit_status != "Not Installed" else None,
        "log_rotation": get_log_rotation(serveur, os_info) if audit_status != "Not Installed" else None
    }

def check_syslog_configuration(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        results = {
            "syslog_installed": "Not Installed",
            "syslog_running": "Stopped",
            "auth_logs_configured": [],
            "sys_events_configured": [],
            "log_files_permissions": {},
            "log_forwarding_secure": "No Forwarding Configured"
        }
        syslog_installed = execute_ssh_command(serveur, "dpkg -l | grep -E 'rsyslog|syslog-ng'")
        results["syslog_installed"] = "Installed" if syslog_installed else "Not Installed"
        syslog_status = execute_ssh_command(serveur, "systemctl is-active rsyslog || systemctl is-active syslog-ng")
        results["syslog_running"] = "Running" if syslog_status and syslog_status[0] == "active" else "Stopped"
        auth_logs_configured = execute_ssh_command(serveur, r"grep -Er '^(auth|authpriv)\.' /etc/rsyslog.* /etc/syslog.*")
        results["auth_logs_configured"] = auth_logs_configured or []
        sys_events_configured = execute_ssh_command(serveur, r"grep -Er '^(\*\.\*|kern\.|daemon\.|^\*\.info)' /etc/rsyslog.* /etc/syslog.*")
        results["sys_events_configured"] = sys_events_configured or []
        log_files = ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages", "/var/log/secure"]
        for log_file in log_files:
            permission_output = execute_ssh_command(serveur, f"stat -c '%a' {log_file} 2>/dev/null")
            if permission_output:
                permissions = permission_output[0].strip()
                results["log_files_permissions"][log_file] = permissions
            else:
                results["log_files_permissions"][log_file] = "Not Found"
        forwarding_conf = execute_ssh_command(serveur, "grep -Er '@@?' /etc/rsyslog.* /etc/syslog.*")
        if forwarding_conf:
            tls_config = execute_ssh_command(serveur, "grep -Ei '(StreamDriverMode|StreamDriverAuthMode|DefaultNetstreamDriver)' /etc/rsyslog.*")
            results["log_forwarding_secure"] = "TLS Enabled" if tls_config else "TLS Not Enabled"
        else:
            results["log_forwarding_secure"] = "No Forwarding Configured"
        return results
    else:
        print(f"[check_syslog_configuration] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); syslog configuration check skipped.")
        return {}

def check_service_log_protection(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        results = {
            "log_files_permissions": {},
            "issues": []
        }
        log_files = {
            "/var/log/syslog": {"owner": "root", "group": "adm", "permissions": "640"},
            "/var/log/auth.log": {"owner": "root", "group": "adm", "permissions": "640"},
            "/var/log/kern.log": {"owner": "root", "group": "adm", "permissions": "640"},
            "/var/log/daemon.log": {"owner": "root", "group": "adm", "permissions": "640"}
        }
        for log_file, expected in log_files.items():
            output = execute_ssh_command(serveur, f"stat -c '%U %G %a' {log_file} 2>/dev/null")
            if output:
                owner, group, permissions = output[0].split()
                detected_info = {
                    "owner": owner,
                    "group": group,
                    "permissions": permissions
                }
            else:
                detected_info = {"owner": "Not Found", "group": "Not Found", "permissions": "Not Found"}
            results[log_file] = detected_info
        return results or None
    else:
        print(f"[check_service_log_protection] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); service log protection check skipped.")
        return {}

def analyse_journalisation(serveur, niveau="min", reference_data=None, os_info=None):
    if reference_data is None:
        reference_data = load_reference_yaml()
    report = {}
    rules = {
        "min": {},
        "moyen": {
            "R33": (check_r33, "Ensure accountability of administrative actions")
        },
        "renforce": {
            "R71": (check_syslog_configuration, "Ensure secure and complete logging configuration"),
            "R72": (check_service_log_protection, "Ensure service log protection against unauthorized access or modification")
        }
    }
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            # Here we pass os_info to the function
            report[rule_id] = check_compliance(rule_id, function(serveur, os_info), reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in logging and auditing.")
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"
    compliance_percentage = (sum(1 for result in report.values() if result["status"] == "Compliant") / len(report) * 100) if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (Logging / Audit) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

    html_yaml_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.yml"

    if os.path.exists(html_yaml_path):
        os.remove(html_yaml_path)
