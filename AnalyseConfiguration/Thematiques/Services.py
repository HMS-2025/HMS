import subprocess
import yaml
import os

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

# Comparer les résultats de l'analyse avec les références
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si une règle est conforme en la comparant avec Reference_Min.yaml."""
    expected_services = reference_data.get(rule_id, {}).get("expected", {}).get("disallowed_services", [])

    # Vérifie quels services actifs sont interdits
    non_compliant_services = [service for service in rule_value if service in expected_services]

    return {
        "status": "Non conforme" if non_compliant_services else "Conforme",
        "services_interdits_detectes": non_compliant_services if non_compliant_services else "Aucun",
        "services_attendus_a_retirer": expected_services,
        "appliquer": False if non_compliant_services else True
    }

# Fonction principale pour analyser les services actifs
def analyse_services(serveur, niveau="min", reference_data=None):
    """Analyse les services actifs et génère un rapport YAML avec conformité."""
    report = {}
    compliance_results = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des services non nécessaires (R62)")
        active_services = get_active_services(serveur)
        compliance_results["R62"] = check_compliance("R62", active_services, reference_data)

    # Structurer le rapport final
    report["R62"] = compliance_results["R62"]

    # Enregistrement du rapport YAML
    save_yaml_report(report, "services_minimal.yml")

    # Vérifier que chaque valeur est un dictionnaire
    total_rules = len(compliance_results)
    conforming_rules = sum(1 for result in compliance_results.values()
                           if isinstance(result, dict) and result.get("status") == "Conforme")

    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    # Affichage des résultats
    print("\n[Résultats de la conformité]")
    for rule, status in compliance_results.items():
        if isinstance(status, dict) and status.get("status") == "Non conforme":
            print(f"- {rule}: {status['status']}")
            print(f"  -> Services interdits trouvés : {status['services_interdits_detectes']}")
        else:
            print(f"- {rule}: {status}")

    print(f"\nTaux de conformité du niveau minimal (Services) : {compliance_percentage:.2f}%")

# R62 - Vérifier les services actifs sur le système
def get_active_services(serveur):
    """Récupère la liste des services actifs sur le serveur."""
    try:
        command_services = "systemctl list-units --type=service --state=running | awk '{print $1}'"
        stdin, stdout, stderr = serveur.exec_command(command_services)
        active_services = stdout.read().decode().strip().split("\n")

        # Filtrer les entrées invalides
        active_services = [service.strip() for service in active_services if service and not service.startswith("LOAD")]

        return active_services
    except Exception as e:
        print(f"Erreur lors de la récupération des services actifs : {e}")
        return []

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")
