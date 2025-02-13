import yaml
import os
import paramiko

# Charger les références depuis Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    """Charge le fichier Reference_min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_min.yaml : {e}")
        return {}

# Exécuter une commande sur le serveur distant et récupérer la sortie
def execute_remote_command(serveur, command, default_output="Non détecté"):
    """Exécute une commande distante et normalise la sortie."""
    try:
        stdin, stdout, stderr = serveur.exec_command(command)
        output = stdout.read().decode().strip()
        return output if output else default_output
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande : {command} -> {e}")
        return default_output

# Comparer les résultats de l'analyse avec les références
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si une règle est conforme en la comparant avec Reference_min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    non_compliant_items = {}

    # Comparer chaque sous-règle
    for key, expected in expected_value.items():
        detected = rule_value.get(key, "Non détecté")
        if detected != expected:
            non_compliant_items[key] = {
                "Détecté": detected,
                "Attendu": expected
            }

    return {
        "status": "Non conforme" if non_compliant_items else "Conforme",
        "éléments_problématiques": non_compliant_items if non_compliant_items else "Aucun",
        "éléments_attendus": expected_value,
        "appliquer": False if non_compliant_items else True
    }

# Fonction principale pour analyser les utilisateurs
def analyse_systeme(serveur, niveau="min", reference_data=None):
    """Analyse les comptes utilisateurs et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Aucune règle spécifique pour le niveau minimal en gestion des utilisateurs.")

    # Enregistrement du rapport
    save_yaml_report(report, "systeme_minimal.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme") if total_rules > 0 else 0
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 100  # 100% si pas de règles

    print(f"\nTaux de conformité du niveau minimal (Systeme) : {compliance_percentage:.2f}%")

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)

    print(f"Rapport généré : {output_path}")
