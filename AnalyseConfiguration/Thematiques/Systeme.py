import yaml
import os

# Load reference configuration from Reference_min.yaml or Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Loads the reference file for the selected level (min or moyen)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return {}

# Compliance check function
def check_compliance(rule_value, expected_value):
    """Checks compliance based on the given rule."""
    
    # Vérification stricte pour garantir que les valeurs sont bien comparées correctement
    if isinstance(rule_value, dict) and isinstance(expected_value, dict):
        is_compliant = all(
            str(rule_value.get(k, "None")) == str(expected_value.get(k, "None"))
            for k in expected_value
        )
    elif isinstance(rule_value, list) and isinstance(expected_value, list):
        is_compliant = sorted(rule_value) == sorted(expected_value)
    else:
        is_compliant = str(rule_value) == str(expected_value)

    return {
        "status": "Compliant" if is_compliant else "Non-compliant",
        "apply": is_compliant,  
        "detected_elements": rule_value,
        "expected_elements": expected_value
    }

# Main function to analyze the system
def analyse_systeme(serveur, niveau, reference_data=None):
    """Analyzes the system and generates a YAML report with compliance results."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml(niveau)

    if niveau == "min":
        print("-> No specific rules for minimal level system analysis.")

    elif niveau == "moyen":
        print("-> Checking memory configuration settings (R8)")
        expected_memory_settings = reference_data.get("R8", {}).get("expected", {}).get("memory_options", [])
        memory_settings = check_memory_configuration(serveur, expected_memory_settings)
        report["R8"] = check_compliance(memory_settings, expected_memory_settings)

        print("-> Checking kernel configuration settings (R9)")
        expected_kernel_settings = reference_data.get("R9", {}).get("expected", {}).get("kernel_settings", {})
        kernel_settings = check_kernel_configuration(serveur, expected_kernel_settings)
        report["R9"] = check_compliance(kernel_settings, expected_kernel_settings)

        print("-> Checking Yama LSM activation (R11)")
        expected_yama_status = reference_data.get("R11", {}).get("expected", {}).get("yama_status", {})
        yama_status = check_yama_lsm(serveur, expected_yama_status)
        report["R11"] = check_compliance(yama_status, expected_yama_status)

        print("-> Checking filesystem configuration settings (R14)")
        expected_filesystem_settings = reference_data.get("R14", {}).get("expected", {}).get("filesystem_settings", {})
        filesystem_settings = check_filesystem_configuration(serveur, expected_filesystem_settings)
        report["R14"] = check_compliance(filesystem_settings, expected_filesystem_settings)

    # Save the report
    save_yaml_report(report, f"system_{niveau}.yml")

    # Calculate compliance rate (ensuring all rules are counted properly)
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Compliant")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 100

    print(f"\nCompliance rate for {niveau.upper()} level (System): {compliance_percentage:.2f}%")

# Save the analysis report
def save_yaml_report(data, output_file):
    """Saves the analysis data into a YAML file in the designated folder."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Report generated: {output_path}")

# --- R8: Memory Configuration Settings ---
def check_memory_configuration(serveur, expected_params):
    """Checks memory configuration parameters in GRUB settings."""

    # Lire la configuration GRUB pour récupérer GRUB_CMDLINE_LINUX_DEFAULT
    command = "grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT=\"//;s/\"$//'"
    stdin, stdout, stderr = serveur.exec_command(command)
    
    # Extraction des options en supprimant les doublons
    grub_cmdline = list(set(stdout.read().decode().strip().split()))

    # Vérifier les éléments détectés
    detected_elements = [param for param in grub_cmdline if param in expected_params]

    # S'assurer que detected_elements est vide si aucun élément n'est trouvé
    return detected_elements if detected_elements else []

# --- R9: Kernel Configuration ---
def check_kernel_configuration(serveur, expected_settings):
    """Checks kernel configuration settings in sysctl based on reference_moyen.yaml."""
    
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()

    return detected_settings

# --- R11: Yama LSM Activation ---
def check_yama_lsm(serveur, expected_value):
    """Checks if Yama LSM is enabled and properly configured."""
    
    command = "sysctl -n kernel.yama.ptrace_scope"
    stdin, stdout, stderr = serveur.exec_command(command)
    yama_status = stdout.read().decode().strip()

    return {"kernel.yama.ptrace_scope": yama_status}

# --- R14: Filesystem Configuration Settings ---
def check_filesystem_configuration(serveur, expected_settings):
    """Checks recommended filesystem settings in sysctl based on reference_moyen.yaml."""
    
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()

    return detected_settings
