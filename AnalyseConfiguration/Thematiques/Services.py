import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Load references from Reference_min.yaml or Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Loads the reference file corresponding to the selected level (min, moyen ou renforce)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Error loading {file_path} : {e}")
        return {}

# Check rule compliance
def check_compliance(rule_id, detected_values, reference_data):
    """Checks rule compliance by comparing detected values with reference data."""
    expected_values = reference_data.get(rule_id, {}).get("expected", {})

    # Specific exception for R62: detected prohibited services
    if rule_id == "R62":
        detected_prohibited_elements = detected_values.get("detected_prohibited_elements", [])
        is_compliant = len(detected_prohibited_elements) == 0

        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": detected_values.get("detected_elements", []),
            "detected_prohibited_elements": detected_prohibited_elements,
            "expected_elements": expected_values
        }

    # Specific exception for R74: interfaces and local delivery
    elif rule_id == "R74":
        detected_interfaces = set(detected_values.get("listen_interfaces", []))
        expected_interfaces = set(expected_values.get("hardened_mail_service", {}).get("listen_interfaces", []))

        detected_local_delivery = set(detected_values.get("allow_local_delivery", []))
        expected_local_delivery = set(expected_values.get("hardened_mail_service", {}).get("allow_local_delivery", []))

        interfaces_compliant = detected_interfaces == expected_interfaces
        local_delivery_compliant = detected_local_delivery == expected_local_delivery

        is_compliant = interfaces_compliant and local_delivery_compliant

        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": {
                "listen_interfaces": list(detected_interfaces),
                "allow_local_delivery": list(detected_local_delivery)
            },
            "expected_elements": {
                "listen_interfaces": list(expected_interfaces),
                "allow_local_delivery": list(expected_local_delivery)
            }
        }

    # Specific case for R75: at least one expected alias must be detected
    elif rule_id == "R75":
        detected_aliases = detected_values.get("detected_elements", [])
        expected_aliases = expected_values.get("mail_aliases", [])
        is_compliant = any(alias in detected_aliases for alias in expected_aliases)

        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": detected_aliases,
            "expected_elements": expected_aliases
        }

    # Nouveau cas pour rule id "10" : Vérifier que /proc/sys/kernel/modules_disabled == 1
    elif rule_id == "R10":
        # On attend que la valeur récupérée soit dans detected_values["detected_elements"]
        is_compliant = (detected_values.get("detected_elements", "") == "1")
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": detected_values.get("detected_elements", ""),
            "expected_elements": "1"
        }

    # Standard handling for other rules
    else:
        return {
            "apply": detected_values == expected_values,
            "status": "Compliant" if detected_values == expected_values else "Non-Compliant",
            "expected_elements": expected_values or "None",
            "detected_elements": detected_values or "None"
        }

# Main function for service analysis
def analyse_services(serveur, niveau, reference_data=None):
    """Analyzes services and generates a detailed YAML compliance report."""
    if reference_data is None:
        reference_data = load_reference_yaml(niveau)
    
    report = {}
    rules = {
        "min": {
            "R62": (disable_unnecessary_services, "Disable prohibited services"),
        },
        "moyen": {
            "R35": (check_unique_service_accounts, "Verify the uniqueness of service accounts"),
            "R63": (check_disabled_service_features, "Disable non-essential service features"),
            "R74": (check_hardened_mail_service, "Harden local mail service"),
            "R75": (check_mail_aliases, "Verify mail aliases for service accounts"),
        },
        "renforce": {
            "R10": (check_kernel_modules_disabled, "Disable kernel modules loading")
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            # Pour R62, on transmet la référence au besoin
            if rule_id == "R62":
                report[rule_id] = check_compliance(rule_id, function(serveur, reference_data), reference_data)
            else:
                report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)

    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = (sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100) if report else 0
    print(f"\nCompliance rate for level {niveau.upper()} : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

# R62 - Disable unnecessary services
def disable_unnecessary_services(serveur, reference_data):
    """Checks active services and determines compliance based on the prohibited services list."""
    
    disallowed_services = reference_data.get("R62", {}).get("expected", {}).get("disallowed_services", [])

    if not disallowed_services:
        print("No prohibited services defined. Check the reference_min.yaml file.")
        return {}

    active_services = get_active_services(serveur)

    forbidden_running_services = [service for service in active_services if service in disallowed_services]

    is_compliant = len(forbidden_running_services) == 0

    return {
        "status": "Compliant" if is_compliant else "Non-Compliant",
        "apply": is_compliant,
        "detected_elements": active_services,
        "detected_prohibited_elements": forbidden_running_services
    }

# Retrieve active services list on a remote machine via SSH
def get_active_services(serveur):
    """Retrieves the list of active services on the remote server."""
    try:
        command_services = "systemctl list-units --type=service --state=running | awk '{print $1}'"
        stdin, stdout, stderr = serveur.exec_command(command_services)
        active_services = stdout.read().decode().strip().split("\n")
        active_services = [service.strip() for service in active_services if service and not service.startswith("LOAD")]
        return active_services
    except Exception as e:
        print(f"Error retrieving active services: {e}")
        return []

# R35 - Use unique and exclusive service accounts
def check_unique_service_accounts(serveur):
    """Checks if each service has a unique system account and correctly formats the results."""
    command = "ps -eo user,comm | awk '{print $1}' | sort | uniq -c"
    stdin, stdout, stderr = serveur.exec_command(command)
    users_count = stdout.read().decode().strip().split("\n")

    non_unique_accounts = [line.strip() for line in users_count if int(line.split()[0]) > 1]

    return non_unique_accounts if non_unique_accounts else []

# R63 - Disable non-essential service features
def check_disabled_service_features(serveur):
    """Checks services with enabled Linux capabilities."""
    command = "find / -type f -perm /111 -exec getcap {} \; 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command)
    capabilities = stdout.read().decode().strip().split("\n")

    return capabilities if capabilities else []

# R74 - Harden the local mail service
def check_hardened_mail_service(serveur):
    """Checks if the mail service only accepts local connections and allows only local delivery."""
    command_listen = "ss -tuln | grep ':25' | awk '{print $5}'"
    stdin, stdout, stderr = serveur.exec_command(command_listen)
    listening_ports = stdout.read().decode().strip().split("\n")

    detected_interfaces = [line.strip() for line in listening_ports if line.strip()]

    command_destination = "postconf -h mydestination"
    stdin, stdout, stderr = serveur.exec_command(command_destination)
    mydestination_raw = stdout.read().decode().strip()

    detected_local_delivery = [item.strip() for item in mydestination_raw.split(",") if item.strip()]

    return {
        "listen_interfaces": detected_interfaces,
        "allow_local_delivery": detected_local_delivery
    }

# R75 - Verify mail aliases for service accounts
def check_mail_aliases(serveur):
    """Checks for the presence of mail aliases for service accounts via a Linux command."""
    command = "grep -E '^[a-zA-Z0-9._-]+:' /etc/aliases | awk -F':' '{print $1}' 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command)
    aliases_output = stdout.read().decode().strip().split("\n")

    reference_data = load_reference_yaml("moyen")
    expected_aliases = reference_data.get("R75", {}).get("expected", {}).get("mail_aliases", [])

    detected_aliases = [alias.strip() for alias in aliases_output if alias.strip()]

    return {
        "detected_elements": detected_aliases,
        "expected_elements": expected_aliases
    }

# Nouveau : Vérification de /proc/sys/kernel/modules_disabled pour s'assurer que sa valeur est 1
def check_kernel_modules_disabled(serveur):
    """
    Vérifie que /proc/sys/kernel/modules_disabled contient la valeur 1.
    """
    try:
        commande = "cat /proc/sys/kernel/modules_disabled"
        stdin, stdout, stderr = serveur.exec_command(commande)
        value = stdout.read().decode().strip()
    except Exception as e:
        print("Erreur lors de la lecture de /proc/sys/kernel/modules_disabled :", e)
        return {
            "status": "Non-Compliant",
            "apply": False,
            "detected_elements": f"Erreur : {e}",
            "expected_elements": "1"
        }
    
    is_compliant = (value == "1")
    return {
        "status": "Compliant" if is_compliant else "Non-Compliant",
        "apply": is_compliant,
        "detected_elements": value if value else "Aucune valeur détectée",
        "expected_elements": "1"
    }

def save_yaml_report(data, output_file, rules, niveau):
    """Saves the analysis results in a YAML file without aliases."""
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    yaml.Dumper.ignore_aliases = lambda *args: True

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("services:\n")
        
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n") 
        file.write("\n")
