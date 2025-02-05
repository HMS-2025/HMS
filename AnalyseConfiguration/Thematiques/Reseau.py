import paramiko
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

# Comparer les services réseau actifs avec la liste des services autorisés/interdits
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si les services actifs sont conformes en fonction de Reference_Min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    allowed_services = expected_value.get("allowed_services", [])
    disallowed_services = expected_value.get("disallowed_services", [])

    detected_services = rule_value  # Liste des services actifs détectés
    non_compliant_services = [service for service in detected_services if service in disallowed_services]
    
    return {
        "status": "Non conforme" if non_compliant_services else "Conforme",
        "services_detectes": detected_services if detected_services else "Aucun service actif détecté",
        "services_non_conformes": non_compliant_services if non_compliant_services else "Aucun",
        "services_attendus": allowed_services,
        "appliquer": False if non_compliant_services else True
    }

# Fonction principale pour analyser la configuration réseau
def analyse_reseau(serveur, niveau="min", reference_data=None):
    """Analyse les services réseau actifs et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des services réseau actifs (R80)")
        active_services = get_active_services(serveur)
        report["R80"] = check_compliance("R80", active_services, reference_data)

    # Enregistrement du rapport
    save_yaml_report(report, "reseau_minimal.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau minimal (Réseau) : {compliance_percentage:.2f}%")

# R80 - Réduire la surface d’attaque des services réseau
def get_active_services(serveur):
    """Récupère la liste des services réseau actifs en écoutant sur les ports."""
    try:
        command_services = "sudo netstat -tulnp | awk '{print $7}' | cut -d'/' -f2 | sort -u"
        stdin, stdout, stderr = serveur.exec_command(command_services)
        active_services = stdout.read().decode().strip().split("\n")
        active_services = [service for service in active_services if service]  # Filtrer les entrées vides
        return active_services
    except Exception as e:
        print(f"Erreur lors de la récupération des services réseau actifs : {e}")
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
