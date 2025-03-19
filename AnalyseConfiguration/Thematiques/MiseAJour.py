import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Loads the YAML reference file and returns its content.
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return {}

# Executes an SSH command on the remote server and returns the output as a list of lines.
def execute_ssh_command(server, command):
    try:
        stdin, stdout, stderr = server.exec_command(command)
        return list(filter(None, stdout.read().decode().strip().split("\n")))
    except Exception as e:
        print(f"Error executing SSH command: {command} - {e}")
        return []

# Compares detected values with expected values for a given rule.
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    
    if not isinstance(expected_values, dict):
        expected_values = {}

    formatted_detected = {
        key: " | ".join(value) if isinstance(value, list) else value
        for key, value in detected_values.items()
    }
    
    formatted_expected = {
        key: " | ".join(value) if isinstance(value, list) else value
        for key, value in expected_values.items()
    }

    # Verification for rule R61 (automatic updates)
    if rule_id == "R61":
        cron_updates = "Cron Updates" in detected_values and detected_values["Cron Updates"] != "No cron job detected"
        cron_scripts = "Cron Scripts" in detected_values and detected_values["Cron Scripts"] == "apt-compat"
        unattended_upgrades = (
            "Unattended Upgrades" in detected_values
            and "enabled" in detected_values["Unattended Upgrades"]
            and "active" in detected_values["Unattended Upgrades"]
            and "inactive" not in detected_values["Unattended Upgrades"]
            and "disabled" not in detected_values["Unattended Upgrades"]
        )
        systemd_timers = "Systemd Timer" in detected_values and "apt-daily.timer" in detected_values["Systemd Timer"]
        is_compliant = ((cron_updates and cron_scripts) or (cron_scripts and unattended_upgrades and systemd_timers))
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "expected_elements": formatted_expected or "None",
            "detected_elements": formatted_detected or "None"
        }
    
    return {
        "apply": set(detected_values) == set(expected_values),
        "status": "Compliant" if set(detected_values) == set(expected_values) else "Non-Compliant",
        "expected_elements": formatted_expected or "None",
        "detected_elements": formatted_detected or "None"
    }

# Checks if a GRUB 2 password is configured.
def check_grub_password(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        cmd_superusers = "grep -E 'set\\s+superusers' /etc/grub.d/* /boot/grub/grub.cfg"
        cmd_password = "grep -E 'password_pbkdf2' /etc/grub.d/* /boot/grub/grub.cfg"
        superusers_output = execute_ssh_command(server, cmd_superusers)
        password_output = execute_ssh_command(server, cmd_password)
        return {
            "apply": bool(superusers_output or password_output),
            "status": "Compliant" if (superusers_output or password_output) else "Non-Compliant",
            "detected_elements": (superusers_output + password_output) or "None"
        }
    else:
        print(f"[check_grub_password] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); GRUB password check skipped.")
        return {
            "apply": False,
            "status": "Not Applicable",
            "detected_elements": {}
        }

# Retrieves the list of installed packages.
def get_installed_packages(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return execute_ssh_command(server, "dpkg --get-selections | grep -v deinstall")
    else:
        print(f"[get_installed_packages] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); installed packages not retrieved.")
        return []

# Retrieves the list of configured package repositories.
def get_trusted_repositories(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return execute_ssh_command(server, "grep -E '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null")
    else:
        print(f"[get_trusted_repositories] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); trusted repositories not retrieved.")
        return []

# Checks the status of automatic updates by retrieving various information.
def get_check_auto_updates(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        unattended = " | ".join(execute_ssh_command(
            server, "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null"
        ))
        enabled = " | ".join(execute_ssh_command(
            server, "systemctl is-enabled unattended-upgrades 2>/dev/null"
        ))
        active = " | ".join(execute_ssh_command(
            server, "systemctl is-active unattended-upgrades 2>/dev/null"
        ))
        apt_conf = " | ".join(execute_ssh_command(
            server, "grep -E '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -q '1' && echo 'enabled' || echo 'disabled'"
        ))
        unattended_upgrades_status = f"{unattended} | {enabled} | {active} | {apt_conf}"
    
        cron_updates = execute_ssh_command(
            server, "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'No cron job detected'"
        )
        if "No cron job detected" not in cron_updates:
            cron_updates = "apt update && apt upgrade -y"
        else:
            cron_updates = "No cron job detected"

        cron_scripts = execute_ssh_command(
            server, "ls -1 /etc/cron.daily/ 2>/dev/null | grep -E '^apt-compat$' || echo 'Not present'"
        )
        cron_scripts = " | ".join(set(cron_scripts))
    
        systemd_timer = execute_ssh_command(
            server, "systemctl list-timers --all | grep -E 'apt-daily |apt-daily-upgrade'"
        )
        systemd_timer = "apt-daily.timer" if systemd_timer else "Not present"
    
        return {
            "Unattended Upgrades": unattended_upgrades_status,
            "Cron Updates": cron_updates,
            "Cron Scripts": cron_scripts,
            "Systemd Timer": systemd_timer
        }
    else:
        print(f"[get_check_auto_updates] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); update status not retrieved.")
        return {}

# Analyzes system update settings and generates a compliance report.
def analyse_mise_a_jour(server, niveau, reference_data, os_info):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R61": (get_check_auto_updates, "Check the status of automatic updates"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            # Pass os_info to the function
            detected_values = function(server, os_info)
            report[rule_id] = check_compliance(rule_id, detected_values, reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.yml"
    compliance_percentage = (sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100) if report else 0
    print(f"\nCompliance rate for level {niveau.upper()} (Updates): {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

# Saves the analysis report in YAML format to the specified directory.
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("updates:\n")
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
