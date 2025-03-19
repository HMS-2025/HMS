import yaml
import os
import paramiko
import re
from GenerationRapport.GenerationRapport import generate_html_report

# Load references from Reference_min.yaml or Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Load the reference file corresponding to the selected level (min or moyen)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Error loading {file_path} : {e}")
        return {}

# Execute an SSH command and return the output as a list of lines
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip().split("\n")
    return list(filter(None, output))

# Check rule compliance by comparing detected values with the reference data
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    
    if isinstance(expected_values, dict):
        expected_values_list = list(expected_values.values())
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    else:
        expected_values_list = [expected_values]
    
    # Specific treatment for rule R36 (umask)
    if rule_id == "R36":
        detected_umask = detected_values.get("umask", "")
        allowed_vals = ["027", "0027", "077", "0077"]
        compliance = detected_umask in allowed_vals 
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "detected_elements": detected_umask if detected_umask else "None"
        }
    # Specific treatment for rule R37 (MAC verification)
    elif rule_id == "R37":
        compliance = any(detected_values.values())
        formatted = [f"{key.replace('_', ' ').capitalize()}: {str(val).lower()}" for key, val in detected_values.items()]
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "expected_elements": "At least one MAC mechanism (SELinux, AppArmor, SMACK, or Tomoyo) should be active",
            "detected_elements": formatted
        }
    # Specific treatment for rule R45 (AppArmor profiles enforcement)
    elif rule_id == "R45":
        compliance = detected_values.get("apply", False)
        detected_list = detected_values.get("detected_elements", [])
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "expected_elements": "All AppArmor profiles should be in enforce mode (complain mode count: 0)",
            "detected_elements": detected_list
        }
    else:
        detected_values_list = detected_values if isinstance(detected_values, list) else list(detected_values.values())
        compliance = detected_values_list == expected_values_list
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "expected_elements": expected_values_list if expected_values_list else "None",
            "detected_elements": detected_values_list if detected_values_list else "None"
        }

# R8 - Check memory configuration parameters in GRUB settings
def check_memory_configuration(serveur, expected_params, os_info=None):
    if os_info and os_info.get("distro", "").lower() != "ubuntu":
        print(f"[check_memory_configuration] Warning: Detected OS {os_info.get('distro', 'unknown')}. Command syntax may differ.")
    command = "grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT=\"//;s/\"$//'"
    stdin, stdout, stderr = serveur.exec_command(command)
    grub_cmdline = list(set(stdout.read().decode().strip().split()))
    detected_elements = [param for param in grub_cmdline if param in expected_params]
    return detected_elements if detected_elements else []

# R9 - Check kernel configuration settings using sysctl
def check_kernel_configuration(serveur, expected_settings, os_info=None):
    if os_info and os_info.get("distro", "").lower() != "ubuntu":
        print(f"[check_kernel_configuration] Warning: Detected OS {os_info.get('distro', 'unknown')}.")
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()
    return detected_settings

# R11 - Check Yama LSM activation status via sysctl
def check_yama_lsm(serveur, expected_value, os_info=None):
    command = "sysctl -n kernel.yama.ptrace_scope"
    stdin, stdout, stderr = serveur.exec_command(command)
    yama_status = stdout.read().decode().strip()
    return {"kernel.yama.ptrace_scope": yama_status}

# R14 - Check filesystem configuration settings using sysctl
def check_filesystem_configuration(serveur, expected_settings, os_info=None):
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()
    return detected_settings

# R36 - Check the umask in /etc/profile 
def check_umask(serveur, expected_value, os_info=None):
    command = "grep -i 'umask' /etc/profile"
    output = execute_ssh_command(serveur, command)
    umask_value = None

    if not output:
        umask_value = "022"  # Default value
    else:
        for line in output:
            if "umask" in line.lower():
                if "=" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        umask_value = parts[1].strip()
                        break
                else:
                    parts = line.split()
                    if len(parts) >= 2:
                        umask_value = parts[1].strip()
                        break
    return {"umask": umask_value}

# --- New Functions for MAC Verification and AppArmor Profiles ---

def is_module_loaded(serveur, module_name, os_info=None):
    try:
        output = execute_ssh_command(serveur, "lsmod")
        for line in output:
            parts = line.split()
            if parts and parts[0] == module_name:
                return True
    except Exception as e:
        return False
    return False

def is_selinux_enabled(serveur, os_info=None):
    try:
        output = execute_ssh_command(serveur, "sestatus")
        for line in output:
            if "Current mode:" in line:
                mode = line.split(":", 1)[1].strip()
                return mode.lower() == "enforcing"
    except Exception as e:
        return False
    return False

def is_apparmor_enabled(serveur, os_info=None):
    try:
        output = execute_ssh_command(serveur, "apparmor_status")
        for line in output:
            if "apparmor module is loaded" in line.lower():
                return True
    except Exception as e:
        return False
    return False

# R37 - Check if any Mandatory Access Control (MAC) mechanism is active on the remote system.
def check_mac_status(serveur, expected_value, os_info=None):
    selinux = is_selinux_enabled(serveur, os_info)
    apparmor = is_apparmor_enabled(serveur, os_info)
    smack = is_module_loaded(serveur, "smack", os_info)
    tomoyo = is_module_loaded(serveur, "tomoyo", os_info)
    
    return {
        "selinux_enforcing": selinux,
        "apparmor_enabled": apparmor,
        "smack_loaded": smack,
        "tomoyo_loaded": tomoyo
    }

def check_apparmor_profiles(serveur, expected_value, os_info=None):
    # Lance la commande avec sudo pour s'assurer d'avoir toutes les infos
    stdin, stdout, stderr = serveur.exec_command("sudo aa-status")
    
    # Force l'attente de la fin du process
    exit_code = stdout.channel.recv_exit_status()
    
    # Récupère TOUT le contenu de la sortie
    output_str = stdout.read().decode().strip()
    # Si vous préférez une liste de lignes :
    lines = output_str.splitlines()
    
    print("DEBUG aa-status output:\n", output_str)
    
    total_profiles = 0
    enforce_profiles = 0
    complain_profiles = 0
    
    # On parcourt chaque ligne pour identifier les nombres qui nous intéressent
    for line in lines:
        match_loaded = re.search(r'(\d+) profiles are loaded', line)
        if match_loaded:
            total_profiles = int(match_loaded.group(1))
            continue
        
        match_enforce = re.search(r'(\d+) profiles? are in enforce mode', line)
        if match_enforce:
            enforce_profiles = int(match_enforce.group(1))
            continue
        
        match_complain = re.search(r'(\d+) profiles? are in complain mode', line)
        if match_complain:
            complain_profiles = int(match_complain.group(1))
            continue
    
    # Détermine la conformité
    compliance = (
        total_profiles > 0 
        and complain_profiles == 0 
        and enforce_profiles == total_profiles
    )
    
    detected_elements_list = [
        f"{total_profiles} total",
        f"{enforce_profiles} enforced",
        f"{complain_profiles} complain"
    ]
    
    return {
        "total_profiles": total_profiles,
        "enforce_profiles": enforce_profiles,
        "complain_profiles": complain_profiles,
        "apply": compliance,
        "detected_elements": detected_elements_list
    }
    
# Save the YAML report with the analysis results without aliases
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "a", encoding="utf-8") as file:
        file.write("system:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n") 
        file.write("\n")

# Main system analysis function: analyzes the system and generates a YAML report with compliance results.
def analyse_systeme(serveur, niveau, reference_data=None, os_info=None):
    if reference_data is None:
        reference_data = load_reference_yaml(niveau)
    
    if os_info:
        print(f"[analyse_systeme] Detected OS: {os_info.get('distro', 'unknown')}")
    else:
        print("[analyse_systeme] OS information not provided, running generic analysis")
    
    report = {}
    rules = {
        "min": {},
        "moyen": {
            "R8": (check_memory_configuration, "Check memory configuration (see reference_moyen.yaml)"),
            "R9": (check_kernel_configuration, "Check kernel configuration (see reference_moyen.yaml)"),
            "R11": (check_yama_lsm, "Check Yama LSM activation (see reference_moyen.yaml)"),
            "R14": (check_filesystem_configuration, "Check filesystem configuration (see reference_moyen.yaml)")
        },
        "renforce": {
            "R36": (check_umask, "Check umask in /etc/profile (accepted values: 027 or 077, default 022)"),
            "R37": (check_mac_status, "Check that MAC is enabled (SELinux, AppArmor, SMACK, or Tomoyo)"),
            "R45": (check_apparmor_profiles, "Ensure all AppArmor profiles are in enforce mode")
        }
    }
    
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            expected_values = reference_data.get(rule_id, {}).get("expected", {})
            # Tenter de passer os_info si la fonction accepte ce paramètre
            try:
                detected_values = function(serveur, expected_values, os_info)
            except TypeError:
                detected_values = function(serveur, expected_values)
            report[rule_id] = check_compliance(rule_id, detected_values, reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in System.")
        
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (System) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
