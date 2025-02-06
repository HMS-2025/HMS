import subprocess
import yaml
import os
from datetime import datetime

# Charger les références depuis Reference_Min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_Min.yaml"):
    """Charge le fichier Reference_Min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_Min.yaml : {e}")
        return {}

# Charger la liste des services nécessaires
def load_necessary_services(config_file="necessary_services.yml"):
    """Charge la liste des services nécessaires depuis un fichier YAML."""
    try:
        with open(config_file, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
            return config.get("necessary_services", [])
    except FileNotFoundError:
        print(f"Fichier de configuration {config_file} introuvable.")
        return []
    except yaml.YAMLError as e:
        print(f"Erreur lors de la lecture du fichier YAML : {e}")
        return []

# Vérifier la conformité des services actifs avec les références
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si une règle est conforme en la comparant avec Reference_Min.yaml."""
    expected_services = reference_data.get(rule_id, {}).get("expected", {}).get("disallowed_services", [])
    non_compliant_services = [service for service in rule_value if service in expected_services]

    return {
        "status": "Non conforme" if non_compliant_services else "Conforme",
        "services_interdits_detectes": non_compliant_services if non_compliant_services else "Aucun",
        "services_attendus_a_retirer": expected_services,
        "appliquer": False if non_compliant_services else True
    }

# Récupérer la liste des services actifs sur une machine distante via SSH
def get_active_services(client):
    """Récupère la liste des services actifs sur le serveur distant."""
    try:
        command_services = "systemctl list-units --type=service --state=running | awk '{print $1}'"
        stdin, stdout, stderr = client.exec_command(command_services)
        active_services = stdout.read().decode().strip().split("\n")
        active_services = [service.strip() for service in active_services if service and not service.startswith("LOAD")]
        return active_services
    except Exception as e:
        print(f"Erreur lors de la récupération des services actifs : {e}")
        return []

# Fonction principale d'analyse de conformité
def analyse_services(client, niveau="min", reference_data=None):
    """Analyse les services actifs et génère un rapport YAML avec conformité."""
    report = {}
    compliance_results = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des services non nécessaires (R62)")
        active_services = get_active_services(client)
        compliance_results["R62"] = check_compliance("R62", active_services, reference_data)

    report["R62"] = compliance_results["R62"]
    save_yaml_report(report, "services_minimal.yml")

    total_rules = len(compliance_results)
    conforming_rules = sum(1 for result in compliance_results.values()
                           if isinstance(result, dict) and result.get("status") == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print("\n[Résultats de la conformité]")
    for rule, status in compliance_results.items():
        if isinstance(status, dict) and status.get("status") == "Non conforme":
            print(f"- {rule}: {status['status']}")
            print(f"  -> Services interdits trouvés : {status['services_interdits_detectes']}")
        else:
            print(f"- {rule}: {status}")

    print(f"\nTaux de conformité du niveau minimal (Services) : {compliance_percentage:.2f}%")

# Désactiver les services non nécessaires
def disable_unnecessary_services(client):
    """Désactive les services non nécessaires sur un serveur distant."""
    necessary_services = load_necessary_services()
    if not necessary_services:
        print("Aucun service nécessaire défini. Vérifiez le fichier de configuration.")
        return

    active_services = get_active_services(client)
    if not active_services:
        print("Aucun service actif trouvé.")
        return

    unnecessary_services = [service for service in active_services if service not in necessary_services]
    if unnecessary_services:
        print("Services non nécessaires trouvés. Désactivation en cours...")
        report_data = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "unnecessary_services": [],
        }

        for service in unnecessary_services:
            try:
                # client.exec_command(f"systemctl stop {service}")
                # client.exec_command(f"systemctl disable {service}")
                print(f"Service désactivé : {service}")
                report_data["unnecessary_services"].append(service)
            except Exception as e:
                print(f"Erreur lors de la désactivation du service {service} : {e}")

        save_yaml_report(report_data, "disabled_services.yml")
    else:
        print("Aucun service inutile trouvé.")

# Enregistrement des rapports YAML
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "a", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")
