import paramiko
import yaml
import os

# Load references from Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    # Load the Reference_min.yaml file and return its content
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error loading Reference_min.yaml: {e}")
        return {}

# Compare analysis results with references
def check_compliance(rule_id, rule_value, reference_data):
    # Check if a rule is compliant by comparing it with Reference_min.yaml
    expected_value = reference_data.get(rule_id, {}).get("expected", {})
    non_compliant_items = {}
    detected_items = {}

    for key, expected in expected_value.items():
        detected = rule_value.get(key, "Not detected")
        if key == "Systemd Timer" and "apt-daily.timer" in detected:
            detected = "apt-daily.timer"
        
        detected_items[key] = detected
        if detected != expected:
            non_compliant_items[key] = {"Detected": detected, "Expected": expected}

    return {
        "status": "Non-compliant" if non_compliant_items else "Compliant",
        "problematic_elements": non_compliant_items if non_compliant_items else "None",
        "detected_elements": detected_items,
        "expected_elements": expected_value,
        "apply": False if non_compliant_items else True
    }

# Verify automatic update status
def get_check_auto_updates(server):
    update_status = {}

    command_unattended_installed = "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null"
    stdin, stdout, stderr = server.exec_command(command_unattended_installed)
    installed_status = stdout.read().decode().strip()

    command_unattended_enabled = "systemctl is-enabled unattended-upgrades 2>/dev/null"
    stdin, stdout, stderr = server.exec_command(command_unattended_enabled)
    enabled_status = stdout.read().decode().strip()

    command_unattended_active = "systemctl is-active unattended-upgrades 2>/dev/null"
    stdin, stdout, stderr = server.exec_command(command_unattended_active)
    active_status = stdout.read().decode().strip()

    command_check_conf = "grep -E '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -q '1' && echo 'enabled' || echo 'disabled'"
    stdin, stdout, stderr = server.exec_command(command_check_conf)
    config_status = stdout.read().decode().strip()

    update_status["Unattended Upgrades"] = f"{installed_status} | {enabled_status} | {active_status} | {config_status}"

    command_cron = "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'No cron job detected'"
    stdin, stdout, stderr = server.exec_command(command_cron)
    output = stdout.read().decode().strip()
    update_status["Cron Updates"] = "apt update && apt upgrade -y" if "apt update && apt upgrade -y" in output else "No cron job detected"

    command_cron_scripts = "ls -1 /etc/cron.daily/ 2>/dev/null | grep -E '^apt-compat$' || echo 'No update script detected'"
    stdin, stdout, stderr = server.exec_command(command_cron_scripts)
    output = stdout.read().decode().strip()
    update_status["Cron Scripts"] = "apt-compat" if "apt-compat" in output else "No update script detected"

    command_systemd_timer = "systemctl list-timers --all | grep -E 'apt-daily|apt-daily-upgrade'"
    stdin, stdout, stderr = server.exec_command(command_systemd_timer)
    output = stdout.read().decode().strip()
    update_status["Systemd Timer"] = "apt-daily.timer" if "apt-daily" in output else "No systemd timer detected"

    return update_status

# Main function to analyze automatic updates
def analyse_mise_a_jour(server, niveau="min", reference_data=None):
    report = {}
    
    if reference_data is None:
        reference_data = load_reference_yaml()
    
    rules = {
        "min": {
            "R61": (get_check_auto_updates, "Verify automatic update status"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(server), reference_data)
    
    save_yaml_report(report, f"update_{niveau}.yaml", rules)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 100
    print(f"\nCompliance rate for {niveau.upper()} niveau (Updates): {compliance_percentage:.2f}%")

# Save analysis report in YAML format
def save_yaml_report(data, output_file, rules):
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "w", encoding="utf-8") as file:
        for rule_id, content in data.items():
            comment = rules.get("min", {}).get(rule_id, (None, ""))[1]
            file.write(f"{rule_id}:  # {comment}\n")
            yaml.dump(content, file, default_flow_style=False, allow_unicode=True, indent=2)
    
    print(f"Report generated: {output_path}")
