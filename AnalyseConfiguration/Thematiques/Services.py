import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

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

# Vérification de conformité des règles
def check_compliance(rule_id, detected_values, reference_data):
    """Vérifie la conformité des règles en comparant les valeurs détectées avec les références."""

    expected_values = reference_data.get(rule_id, {}).get("expected", {})

    # Exception spécifique pour R62 : services interdits détectés
    if rule_id == "R62":
        detected_prohibited_elements = detected_values.get("detected_prohibited_elements", [])
        is_compliant = len(detected_prohibited_elements) == 0

        return {
            "apply": is_compliant,
            "status": "Conforme" if is_compliant else "Non-conforme",
            "detected_elements": detected_values.get("detected_elements", []),
            "detected_prohibited_elements": detected_prohibited_elements,
            "expected_elements": expected_values
        }

    # Exception spécifique pour R74 : interfaces et livraison locales
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
            "status": "Conforme" if is_compliant else "Non-conforme",
            "detected_elements": {
                "listen_interfaces": list(detected_interfaces),
                "allow_local_delivery": list(detected_local_delivery)
            },
            "expected_elements": {
                "listen_interfaces": list(expected_interfaces),
                "allow_local_delivery": list(expected_local_delivery)
            }
        }

    # Cas spécifique pour R75 : au moins un alias attendu détecté
    elif rule_id == "R75":
        detected_aliases = detected_values.get("detected_elements", [])
        expected_aliases = expected_values.get("mail_aliases", [])
        is_compliant = any(alias in detected_aliases for alias in expected_aliases)

        return {
            "apply": is_compliant,
            "status": "Conforme" if is_compliant else "Non-conforme",
            "detected_elements": detected_aliases,
            "expected_elements": expected_aliases
        }

    # Gestion standard pour les autres règles
    else:
        return {
            "apply": detected_values == expected_values,
            "status": "Conforme" if detected_values == expected_values else "Non-conforme",
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
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Conforme") / len(report) * 100 if report else 0
    print(f"\nTaux de conformité pour le niveau {niveau.upper()} : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

# R62 - Désactiver les services non nécessaires
def disable_unnecessary_services(serveur, reference_data):
    """Vérifie les services actifs et établit la conformité en fonction de la liste des services interdits."""
    
    # Charger les services interdits depuis reference_min.yaml
    disallowed_services = reference_data.get("R62", {}).get("expected", {}).get("disallowed_services", [])

    if not disallowed_services:
        print("Aucun service interdit défini. Vérifiez le fichier reference_min.yaml.")
        return {}

    # Récupérer la liste des services actifs
    active_services = get_active_services(serveur)

    # Détecter les services interdits en cours d'exécution
    forbidden_running_services = [service for service in active_services if service in disallowed_services]

    # Déterminer la conformité
    is_compliant = len(forbidden_running_services) == 0

    return {
        "status": "Conforme" if is_compliant else "Non-conforme",
        "apply": is_compliant,
        "detected_elements": active_services,  # Liste complète des services en cours d'exécution
        "detected_prohibited_elements": forbidden_running_services  # Liste des services interdits détectés
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

    # Vérifier si un service écoute uniquement en local
    command_listen = "ss -tuln | grep ':25' | awk '{print $5}'"
    stdin, stdout, stderr = serveur.exec_command(command_listen)
    listening_ports = stdout.read().decode().strip().split("\n")

    detected_interfaces = [line.strip() for line in listening_ports if line.strip()]

    # Vérifier la configuration de livraison locale avec Postfix
    command_destination = "postconf -h mydestination"
    stdin, stdout, stderr = serveur.exec_command(command_destination)
    mydestination_raw = stdout.read().decode().strip()

    # Correct : un seul split ici !
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

    return {  # <-- Ajoute explicitement ce return !
        "detected_elements": detected_aliases,
        "expected_elements": expected_aliases
    }

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
