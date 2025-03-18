import yaml
import os
from GenerationRapport.GenerationRapport import generate_html_report

# Execute an SSH command on the remote server and return the result
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Load references from Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error loading  {file_path} : {e}")
        return {}

# Compare analysis results with reference data
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = []

    if rule_id == 'R71':
        detected = detected_values or {}
        issues = []

        # syslog installed
        if not detected.get("syslog_installed") == "Installed":
            issues.append(f"Syslog: '{detected.get('syslog_installed')}' (expected 'Installed')")

        # syslog running
        if not detected.get("syslog_running") == "Running":
            issues.append(f"Syslog service: '{detected.get('syslog_running')}' (expected 'Running')")

        # Authentication logs configuration
        if not detected["auth_logs_configured"]:
            issues.append("Missing authentication logging configuration")

        # system events logs configuration
        if not detected["sys_events_configured"]:
            issues.append("System event logging configuration missing")

        # log files permissions
        for logfile, expected_perm in expected_values["log_files_permissions"].items():
            detected_perm = detected["log_files_permissions"].get(logfile, "Not Found")
            if detected_perm != expected_perm:
                issues.append(f"{logfile}: permissions '{detected_perm}' (expected '{expected_perm}')")

        # log forwarding secure
        if detected["log_forwarding_secure"] != expected_values["log_forwarding_secure"]:
            issues.append(f"Log forwarding security: '{detected['log_forwarding_secure']}' (expected '{expected_values['log_forwarding_secure']}')")

        return {
            "apply": not bool(issues),
            "status": "Compliant" if not issues else "Non-Compliant",
            "expected_elements": expected_values,
            "detected_elements": detected,
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

# Specific functions for logging rules
def get_audit_log_status(serveur):
    result = execute_ssh_command(serveur, "systemctl is-active auditd")
    if not result:
        return "Not Installed"
    if "inactive" in result:
        return "inactive"
    if "active" in result:
        return "active"
    return "Unknown"

def get_log_rotation(serveur):
    return execute_ssh_command(serveur, "cat /etc/logrotate.conf | grep rotate") if get_audit_log_status(serveur) != "Not Installed" else None

def get_auditd_configuration(serveur):
    return execute_ssh_command(serveur, "auditctl -l") if get_audit_log_status(serveur) != "Not Installed" else None

def get_admin_command_logging(serveur):
    return execute_ssh_command(serveur, "grep -E 'execve' /etc/audit/audit.rules") if get_audit_log_status(serveur) != "Not Installed" else None

def get_audit_log_protection(serveur):
    return execute_ssh_command(serveur, "ls -l /var/log/audit/") if get_audit_log_status(serveur) != "Not Installed" else None

def check_r33(serveur):
    audit_status = get_audit_log_status(serveur)
    return {
        "audit_log_status": audit_status,
        "auditd_configuration": get_auditd_configuration(serveur) if audit_status != "Not Installed" else None,
        "admin_command_logging": get_admin_command_logging(serveur) if audit_status != "Not Installed" else None,
        "audit_log_protection": get_audit_log_protection(serveur) if audit_status != "Not Installed" else None,
        "log_rotation": get_log_rotation(serveur) if audit_status != "Not Installed" else None
    }

# Check secure and complete syslog configuration (R71)
def check_syslog_configuration(serveur):
    results = {
        "syslog_installed": "Not Installed",
        "syslog_running": "Stopped",
        "auth_logs_configured": [],
        "sys_events_configured": [],
        "log_files_permissions": {},
        "log_forwarding_secure": "No Forwarding Configured"
    }

    # Check if syslog (rsyslog or syslog-ng) is installed
    syslog_installed = execute_ssh_command(
        serveur,
        "dpkg -l | grep -E 'rsyslog|syslog-ng'"
    )
    results["syslog_installed"] = "Installed" if syslog_installed else "Not Installed"

    # Check if syslog service is running
    syslog_status = execute_ssh_command(
        serveur,
        "systemctl is-active rsyslog || systemctl is-active syslog-ng"
    )
    results["syslog_running"] = "Running" if syslog_status and syslog_status[0] == "active" else "Stopped"

    # Check configuration for authentication logs
    auth_logs_configured = execute_ssh_command(
        serveur,
        r"grep -Er '^(auth|authpriv)\.' /etc/rsyslog.* /etc/syslog.*"
    )
    results["auth_logs_configured"] = auth_logs_configured or []

    # Check configuration for system event logs
    sys_events_configured = execute_ssh_command(
        serveur,
        r"grep -Er '^(\*\.\*|kern\.|daemon\.|^\*\.info)' /etc/rsyslog.* /etc/syslog.*"
    )
    results["sys_events_configured"] = sys_events_configured or []

    # Check permissions of critical log files
    log_files = ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages", "/var/log/secure"]
    for log_file in log_files:
        permission_output = execute_ssh_command(
            serveur,
            f"stat -c '%a' {log_file} 2>/dev/null"
        )
        if permission_output:
            permissions = permission_output[0].strip()
            results["log_files_permissions"][log_file] = permissions
        else:
            results["log_files_permissions"][log_file] = "Not Found"

    # Check if log forwarding is configured securely (TLS)
    forwarding_conf = execute_ssh_command(
        serveur,
        "grep -Er '@@?' /etc/rsyslog.* /etc/syslog.*"
    )

    if forwarding_conf:
        tls_config = execute_ssh_command(
            serveur,
            "grep -Ei '(StreamDriverMode|StreamDriverAuthMode|DefaultNetstreamDriver)' /etc/rsyslog.*"
        )
        results["log_forwarding_secure"] = "TLS Enabled" if tls_config else "TLS Not Enabled"
    else:
        results["log_forwarding_secure"] = "No Forwarding Configured"

    return results

# Main function to analyze logging and auditing
def analyse_journalisation(serveur, niveau="min", reference_data=None):
    if reference_data is None:
        reference_data = load_reference_yaml()
    
    report = {}
    rules = {
        "min": {},
        "moyen": {
            "R33": (check_r33, "Ensure accountability of administrative actions")
        },
        "renforce": {
            "R71": (check_syslog_configuration, "Ensure secure and complete logging configuration")
        }
    }
    
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in logging and auditing.")
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = (sum(1 for result in report.values() if result["status"] == "Compliant") / len(report) * 100) if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (Logging / Audit) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

# Save the analysis report in YAML format
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
