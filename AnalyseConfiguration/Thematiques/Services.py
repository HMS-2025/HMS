import yaml
import os
import paramiko

# Charger les références depuis Reference_min.yaml ou Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Charge le fichier de référence correspondant au niveau choisi (min ou moyen)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}

# Exécution d'une commande SSH
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Vérification de conformité des règles
def check_compliance(rule_id, detected_values, reference_data):
    """Vérifie la conformité des règles en comparant les valeurs détectées avec les références."""
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = []
    
    if isinstance(expected_values, dict):
        for key, value in expected_values.items():
            if isinstance(value, list):
                expected_values_list.extend(value)
            else:
                expected_values_list.append(value)
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    
    return {
        "apply": detected_values == expected_values_list,
        "status": "Conforme" if detected_values == expected_values_list else "Non-conforme",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }

# Fonction principale d'analyse des services
def analyse_services(serveur, niveau, reference_data=None):
    """Analyse les services et génère un rapport YAML détaillé avec la conformité."""
    if reference_data is None:
        reference_data = load_reference_yaml(niveau)
    
    report = {}
    rules = {
        "min": {
            "R62": (disable_unnecessary_services, "Désactiver les services interdits"),
        },
        "moyen": {
            "R35": (check_unique_service_accounts, "Vérifier l'unicité des comptes de service"),
            "R63": (check_disabled_service_features, "Désactiver les fonctionnalités de service non essentielles"),
            "R74": (check_hardened_mail_service, "Renforcer le service de messagerie local"),
            "R75": (check_mail_aliases, "Vérifier les alias de messagerie pour les comptes de service"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Vérification de la règle {rule_id} # {comment}")
            if rule_id == "R62":
                report[rule_id] = check_compliance(rule_id, function(serveur, reference_data), reference_data)
            else:
                report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)

    save_yaml_report(report, f"analyse_{niveau}.yml")
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Conforme") / len(report) * 100 if report else 0
    print(f"\nTaux de conformité pour le niveau {niveau.upper()} : {compliance_percentage:.2f}%")

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

def save_yaml_report(data, output_file):
    """Sauvegarde les résultats de l'analyse dans un fichier YAML sans alias."""
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    yaml.Dumper.ignore_aliases = lambda *args : True

    with open(output_path, "a", encoding="utf-8") as file:
        yaml.dump({"services": data}, file, default_flow_style=False, allow_unicode=True, sort_keys=False, default_style=None)
    print(f"Rapport généré : {output_path}")
