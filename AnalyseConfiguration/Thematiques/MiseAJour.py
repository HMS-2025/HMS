import yaml
import os
import paramiko

# Execute an SSH command on the remote server and return the result
def execute_ssh_command(server, command):
    stdin, stdout, stderr = server.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Check compliance of rules by comparing detected vs expected values
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", [])
    expected_values = expected_values if isinstance(expected_values, list) else []

    return {
        "apply": False if detected_values else True,
        "status": "Compliant" if not detected_values else "Non-compliant",
        "expected_elements": expected_values,
        "detected_elements": detected_values or "None"
    }

# Retrieve the status of automatic updates
def get_check_auto_updates(server):
    update_status = {
        "Unattended Upgrades": execute_ssh_command(
            server, "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null"
        ),
        "Service Enabled": execute_ssh_command(
            server, "systemctl is-enabled unattended-upgrades 2>/dev/null"
        ),
        "Service Active": execute_ssh_command(
            server, "systemctl is-active unattended-upgrades 2>/dev/null"
        ),
        "APT Periodic Config": execute_ssh_command(
            server, "grep -E '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -q '1' && echo 'enabled' || echo 'disabled'"
        ),
        "Cron Jobs": execute_ssh_command(
            server, "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'No cron job detected'"
        ),
        "Cron Scripts": execute_ssh_command(
            server, "ls -1 /etc/cron.daily/ 2>/dev/null | grep -E '^apt-compat$' || echo 'No update script detected'"
        ),
        "Systemd Timer": execute_ssh_command(
            server, "systemctl list-timers --all | grep -E 'apt-daily|apt-daily-upgrade'"
        ),
    }

    return update_status

# Analyze system update settings and generate a compliance report
def analyse_mise_a_jour(server, niveau, reference_data):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R61": (get_check_auto_updates, "Verify automatic update status"),
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(server), reference_data)

    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 0
    print(f"\nCompliance rate for {niveau.upper()} level (Updates): {compliance_percentage:.2f}%")

# Save the analysis report in YAML format
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("mise_a_jour:\n")

        for rule_id, content in data.items():
            comment = rules.get(niveau, {}).get(rule_id, (None, ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n") 
        file.write("\n") 

    print(f"Report generated: {output_path}")
