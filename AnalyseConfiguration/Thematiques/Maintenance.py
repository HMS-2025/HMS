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

    if isinstance(expected_value, list):
        detected_values = rule_value.get("unnecessary_packages", [])
        if not isinstance(detected_values, list):
            detected_values = []

        non_compliant_items["unnecessary_packages"] = [
            pkg for pkg in detected_values if pkg not in expected_value
        ]
    else:
        for key, expected in expected_value.items():
            detected = rule_value.get(key, "Not detected")
            if detected != expected:
                non_compliant_items[key] = {"Detected": detected, "Expected": expected}

    return {
        "status": "Non-compliant" if non_compliant_items else "Compliant",
        "problematic_elements": non_compliant_items if non_compliant_items else "None",
        "expected_elements": expected_value,
        "apply": False if non_compliant_items else True
    }

# Verify GRUB password configuration
def check_grub_password(server):
    command_check_grub_cfg = "grep -E 'set\\s+superusers' /etc/grub.d/* /boot/grub/grub.cfg"
    command_check_password = "grep -E 'password_pbkdf2' /etc/grub.d/* /boot/grub/grub.cfg"
    
    stdin, stdout, stderr = server.exec_command(command_check_grub_cfg)
    superusers_output = stdout.read().decode().strip()
    
    stdin, stdout, stderr = server.exec_command(command_check_password)
    password_output = stdout.read().decode().strip()
    
    return {"status": "Compliant" if superusers_output and password_output else "Non-compliant",
            "message": "A GRUB 2 password is correctly configured." if superusers_output and password_output 
            else "No GRUB 2 password detected. Please configure it."}

# Verify installed packages
def check_installed_packages(server, reference_data):
    expected_packages = reference_data.get("R58", {}).get("expected", [])
    command = "dpkg --get-selections | grep -v deinstall"
    stdin, stdout, stderr = server.exec_command(command)
    installed_packages = stdout.read().decode().strip().split("\n")
    
    unnecessary_packages = [pkg.split()[0] for pkg in installed_packages if pkg.split()[0] not in expected_packages]
    return {"unnecessary_packages": unnecessary_packages} if unnecessary_packages else {"unnecessary_packages": "No unnecessary packages detected"}

# Verify trusted package repositories
def check_trusted_repositories(server):
    command = "grep -E '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null"
    stdin, stdout, stderr = server.exec_command(command)
    repositories = stdout.read().decode().strip().split("\n")
    return {"trusted_repositories": repositories} if repositories else {"trusted_repositories": "No repositories detected"}

# Main function to analyze maintenance
def analyse_maintenance(server, niveau="min", reference_data=None):
    report = {}
    
    if reference_data is None:
        reference_data = load_reference_yaml()
    
    rules = {
        "min": {
            "R58": (check_installed_packages, "Install only strictly necessary packages"),
            "R59": (lambda server, ref_data: check_trusted_repositories(server), "Use trusted package repositories"),
        },
        "moyen": {
            "R5": (lambda server, ref_data: check_grub_password(server), "Ensure a GRUB 2 password is configured"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(server, reference_data), reference_data)
    
    save_yaml_report(report, f"maintenance_{niveau}.yaml", rules)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 100
    print(f"\nCompliance rate for {niveau.upper()} level (Maintenance): {compliance_percentage:.2f}%")

# Save analysis report in YAML format
def save_yaml_report(data, output_file, rules):
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "w", encoding="utf-8") as file:
        for rule_id, content in data.items():
            comment = rules.get("min", {}).get(rule_id, (None, ""))[1] or rules.get("moyen", {}).get(rule_id, (None, ""))[1]
            file.write(f"{rule_id}:  # {comment}\n")
            yaml.dump(content, file, default_flow_style=False, allow_unicode=True, indent=2)
    
    print(f"Report generated: {output_path}")
