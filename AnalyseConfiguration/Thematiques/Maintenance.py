import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Load the YAML reference file
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return {}

# Execute an SSH command and return the output
def execute_ssh_command(server, command):
    try:
        stdin, stdout, stderr = server.exec_command(command)
        return list(filter(None, stdout.read().decode().strip().split("\n")))
    except Exception as e:
        print(f"Error executing SSH command: {command} - {e}")
        return []

# Check rule compliance
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", [])
    expected_values = expected_values if isinstance(expected_values, list) else []
    
    return {
        "apply": set(detected_values) == set(expected_values),
        "status": "Compliant" if set(detected_values) == set(expected_values) else "Non-Compliant",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }

# Check if a GRUB 2 password is set
def check_grub_password(server):
    command_check_superusers = "grep -E 'set\\s+superusers' /etc/grub.d/* /boot/grub/grub.cfg"
    command_check_password = "grep -E 'password_pbkdf2' /etc/grub.d/* /boot/grub/grub.cfg"
    
    superusers_output = execute_ssh_command(server, command_check_superusers)
    password_output = execute_ssh_command(server, command_check_password)
    
    return {
        "apply": bool(superusers_output or password_output),
        "status": "Compliant" if superusers_output or password_output else "Non-Compliant",
        "detected_elements": superusers_output + password_output or "None"
    }

# Get the list of installed packages
def get_installed_packages(server):
    return execute_ssh_command(server, "dpkg --get-selections | grep -v deinstall")

# Check installed packages
def check_installed_packages(server, reference_data):
    expected_packages = reference_data.get("R58", {}).get("expected", [])
    installed_packages = get_installed_packages(server)
    unnecessary_packages = [pkg.split()[0] for pkg in installed_packages if pkg.split()[0] not in expected_packages]
    
    return check_compliance("R58", unnecessary_packages, reference_data)

# Get configured package repositories
def get_trusted_repositories(server):
    return execute_ssh_command(server, "grep -E '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null")

# Analyze maintenance and generate a report
def analyse_maintenance(server, niveau, reference_data):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R58": (check_installed_packages, "Install only strictly necessary packages"),
            "R59": (get_trusted_repositories, "Use trusted package repositories"),
        },
        "moyen": {
            "R5": (check_grub_password, "Ensure a GRUB 2 password is configured"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            detected_values = function(server, reference_data) if "reference_data" in function.__code__.co_varnames else function(server)
            
            if isinstance(detected_values, list) or not isinstance(detected_values, dict):  
                report[rule_id] = {
                    "apply": bool(detected_values),
                    "status": "Non-Compliant" if detected_values else "Compliant",
                    "detected_elements": detected_values or "None"
                }
            else:
                report[rule_id] = detected_values
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = sum(1 for r in report.values() if isinstance(r, dict) and r.get("status") == "Compliant") / len(report) * 100 if report else 0
    print(f"\nCompliance rate for level {niveau.upper()} (Maintenance): {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
# Sauvegarder le rapport d'analyse au format YAML

def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("maintenance:\n")
        
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n") 
        file.write("\n")
    
    print(f"Report generated: {output_path}")
