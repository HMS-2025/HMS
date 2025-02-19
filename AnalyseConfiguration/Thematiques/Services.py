import yaml
import os
from datetime import datetime

# Load references from Reference_min.yaml or Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Loads the reference file corresponding to the chosen level (min or moyen)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Error loading {file_path} : {e}")
        return {}

# Compliance check adapted for each rule
def check_compliance(rule_id, rule_value, reference_data):
    """Checks compliance based on the given rule."""

    # Retrieve rule description
    description = reference_data.get(rule_id, {}).get("description", "No description available.")

    # Récupération des valeurs attendues et détectées selon la règle
    if rule_id == "R74":
        expected_value = reference_data.get(rule_id, {}).get("expected", {}).get("hardened_mail_service", {}).get("listen_interfaces", []) + \
                         reference_data.get(rule_id, {}).get("expected", {}).get("hardened_mail_service", {}).get("allow_local_delivery", [])
        detected_value = rule_value.get("detected_elements", [])
    elif rule_id == "R75":
        expected_value = reference_data.get(rule_id, {}).get("expected", {}).get("mail_aliases", [])
        detected_value = rule_value.get("éléments_detectés", [])
    else:
        expected_value = reference_data.get(rule_id, {}).get("expected", [])
        detected_value = rule_value

    if not isinstance(expected_value, list):
        expected_value = []

    # Vérifier la conformité
    is_compliant = bool(detected_value) and set(detected_value).issubset(set(expected_value))

    return {
        "description": description,
        "status": "Compliant" if is_compliant else "Non-compliant",
        "apply": is_compliant,  
        "detected_elements": detected_value if detected_value else [],
        "expected_elements": expected_value
    }

# Main function for analyzing services
def analyse_services(serveur, niveau, reference_data=None):
    """Analyzes services and generates a YAML report with compliance details."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml(niveau)

    if niveau == "min":
        print("-> Checking prohibited services running (R62)")
        forbidden_services = disable_unnecessary_services(serveur, reference_data)
        report["R62"] = forbidden_services

    elif niveau == "moyen":
        print("-> Checking uniqueness of service accounts (R35)")
        unique_service_accounts = check_unique_service_accounts(serveur)
        report["R35"] = check_compliance("R35", unique_service_accounts, reference_data)

        print("-> Checking non-essential service features (R63)")
        disabled_features = check_disabled_service_features(serveur)
        report["R63"] = check_compliance("R63", disabled_features, reference_data)

        print("-> Checking local mail service configuration (R74)")
        hardened_mail_service = check_hardened_mail_service(serveur)
        report["R74"] = check_compliance("R74", hardened_mail_service, reference_data)

        print("-> Checking mail aliases for service accounts (R75)")
        mail_aliases = check_mail_aliases(serveur)
        report["R75"] = check_compliance("R75", mail_aliases, reference_data)

    # Save report
    save_yaml_report(report, f"services_{niveau}.yml")

    # Compliance rate calculation
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Compliant")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nCompliance rate for level {niveau.upper()} (Services) : {compliance_percentage:.2f}%")

# R62 - Disable unnecessary services
def disable_unnecessary_services(serveur, reference_data):
    """Vérifie les services actifs et établit la conformité en fonction de la liste des services interdits."""
    
     # Load prohibited services from reference_min.yaml
    disallowed_services = reference_data.get("R62", {}).get("expected", {}).get("disallowed_services", [])

    if not disallowed_services:
        print("No prohibited services defined. Check the reference_min.yaml file.")
        return []

    # Retrieve active services list
    active_services = get_active_services(serveur)

    # Prohibited services that are running
    forbidden_running_services = [service for service in active_services if service in disallowed_services]

    # Compliance verification
    is_compliant = len(forbidden_running_services) == 0

    return {
        "status": "Compliant" if is_compliant else "Non-compliant",
        "apply": is_compliant,
        "detected_elements": active_services,  # Complete list of running services
        "detected_prohibited_elements": forbidden_running_services,  # Only detected prohibited services
        "expected_elements": disallowed_services  # List of services that should not be active
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
    
# Medium-level rules -------------------------------------------
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

    # Vérifier si un service écoute sur le port 25
    command_listen = "ss -tulnp | awk '$5 ~ /:25$/ {print $5}'"
    stdin, stdout, stderr = serveur.exec_command(command_listen)
    listening_ports = stdout.read().decode().strip().split("\n")

    # Vérifier la configuration de la livraison locale avec Postfix
    command_destination = "postconf -h mydestination"
    stdin, stdout, stderr = serveur.exec_command(command_destination)
    mydestination = stdout.read().decode().strip()

    # Charger la référence attendue
    reference_data = load_reference_yaml("moyen")
    expected_interfaces = reference_data.get("R74", {}).get("expected", {}).get("hardened_mail_service", {}).get("listen_interfaces", [])
    expected_local_delivery = reference_data.get("R74", {}).get("expected", {}).get("hardened_mail_service", {}).get("allow_local_delivery", [])

    # Vérifier que le service écoute uniquement sur 127.0.0.1 ou [::1]
    detected_interfaces = [line.strip() for line in listening_ports if line.strip()]

    # Vérifier que Postfix n'accepte que les mails locaux
    detected_local_delivery = [item.strip() for item in mydestination.split(",")]

    # Si aucun service de messagerie n'est détecté, la règle est conforme
    if not detected_interfaces:
        return {
            "detected_elements": [],
            "expected_elements": expected_interfaces + expected_local_delivery
        }

    return {
        "detected_elements": detected_interfaces + detected_local_delivery,
        "expected_elements": expected_interfaces + expected_local_delivery
    }


# R75 - Verify mail aliases for service accounts
def check_mail_aliases(serveur):
    """Checks for the presence of mail aliases for service accounts via a Linux command."""
    
    # Nouvelle commande pour extraire uniquement les alias
    command = "grep -E '^[a-zA-Z0-9._-]+:' /etc/aliases | awk -F':' '{print $1}' 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command)
    aliases_output = stdout.read().decode().strip().split("\n")

    reference_data = load_reference_yaml("moyen")  # Charger la configuration pour le niveau moyen
    expected_aliases = reference_data.get("R75", {}).get("expected", {}).get("mail_aliases", [])

    # Nettoyage des alias détectés pour éviter des espaces superflus
    detected_aliases = [alias.strip() for alias in aliases_output if alias.strip() in expected_aliases]

    return {
        "éléments_detectés": detected_aliases,
        "éléments_attendus": expected_aliases
    }


# Save YAML reports
def save_yaml_report(data, output_file):
    """Saves analysis data to a YAML file."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Report generated: {output_path}")