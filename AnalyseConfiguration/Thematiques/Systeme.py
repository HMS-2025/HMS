import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Load references from Reference_min.yaml or Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Loads the reference file corresponding to the selected level (min or moyen)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Error loading {file_path} : {e}")
        return {}

# Execute an SSH command
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip().split("\n")
    return list(filter(None, output))

# Check rule compliance
def check_compliance(rule_id, detected_values, reference_data):
    """Checks rule compliance by comparing detected values with reference data."""
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    
    if isinstance(expected_values, dict):
        expected_values_list = list(expected_values.values())
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    else:
        expected_values_list = [expected_values]
    
    detected_values_list = detected_values if isinstance(detected_values, list) else list(detected_values.values())
    
    
    return {
        "apply": detected_values_list == expected_values_list,
        "status": "Compliant" if detected_values_list == expected_values_list else "Non-Compliant",
        "expected_elements": expected_values_list if expected_values_list else "None",
        "detected_elements": detected_values_list if detected_values_list else "None"
    }

# Main system analysis function
def analyse_systeme(serveur, niveau, reference_data=None):
    """Analyzes the system and generates a YAML report with compliance results."""
    if reference_data is None:
        reference_data = load_reference_yaml(niveau)
    
    report = {}
    rules = {
        "min": {},
        "moyen": {
            "R8": (check_memory_configuration, "Verify memory configuration (To see what the values correspond to, check reference_moyen.yaml)"),
            "R9": (check_kernel_configuration, "Verify kernel configuration (To see what the values correspond to, check reference_moyen.yaml)"),
            "R11": (check_yama_lsm, "Verify Yama LSM activation (To see what the values correspond to, check reference_moyen.yaml)"),
            "R14": (check_filesystem_configuration, "Verify filesystem configuration (To see what the values correspond to, check reference_moyen.yaml)"),
        }
    }

    
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            expected_values = reference_data.get(rule_id, {}).get("expected", {})
            detected_values = function(serveur, expected_values)
            report[rule_id] = check_compliance(rule_id, detected_values, reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in System.")
        
    save_yaml_report(report, f"analyse_{niveau}.yml")
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (System) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

#R8 Memory Configuration Settings
def check_memory_configuration(serveur, expected_params):
    """Checks memory configuration parameters in GRUB settings."""

    command = "grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT=\"//;s/\"$//'"
    stdin, stdout, stderr = serveur.exec_command(command)
    
    grub_cmdline = list(set(stdout.read().decode().strip().split()))

    detected_elements = [param for param in grub_cmdline if param in expected_params]

    return detected_elements if detected_elements else []

#R9 Kernel Configuration
def check_kernel_configuration(serveur, expected_settings):
    """Checks kernel configuration settings in sysctl based on reference_moyen.yaml."""
    
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()

    return detected_settings

#R11 Yama LSM Activation
def check_yama_lsm(serveur, expected_value):
    """Checks if Yama LSM is enabled and properly configured."""
    
    command = "sysctl -n kernel.yama.ptrace_scope"
    stdin, stdout, stderr = serveur.exec_command(command)
    yama_status = stdout.read().decode().strip()

    return {"kernel.yama.ptrace_scope": yama_status}

#R14 Filesystem Configuration Settings
def check_filesystem_configuration(serveur, expected_settings):
    """Checks recommended filesystem settings in sysctl based on reference_moyen.yaml."""
    
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()

    return detected_settings

# Sauvegarde du rapport YAML
def save_yaml_report(data, output_file):
    """Saves the analysis results in a YAML file without aliases."""
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "a", encoding="utf-8") as file:
        yaml.safe_dump({"system": data}, file, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"Report generated : {output_path}")
