import subprocess
import yaml
import os
import pwd
import grp

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
    expected_value = reference_data.get(rule_id, {}).get("expected", [])

    if isinstance(expected_value, list):
        # Vérifie si des fichiers non conformes existent
        non_compliant_items = [item for item in rule_value if item not in expected_value]
        return {
            "status": "Non conforme" if non_compliant_items else "Conforme",
            "elements_detectes": non_compliant_items if non_compliant_items else "Aucun",
            "elements_attendus": expected_value,
            "appliquer": False if non_compliant_items else True
        }

    return {
        "status": "Conforme" if rule_value == expected_value else "Non conforme",
        "elements_detectes": rule_value,
        "elements_attendus": expected_value,
        "appliquer": rule_value == expected_value
    }

# Fonction principale pour analyser la gestion des accès
def analyse_gestion_acces(serveur, niveau="min", reference_data=None):
    """Analyse la gestion des accès et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification de la désactivation des comptes inutilisés (R30)")
        inactive_accounts = get_inactive_users()
        report["R30"] = check_compliance("R30", inactive_accounts, reference_data)

        print("-> Vérification des fichiers sans propriétaire (R53)")
        orphan_files = find_orphan_files("/")
        report["R53"] = check_compliance("R53", orphan_files, reference_data)

        print("-> Vérification des exécutables avec setuid/setgid (R56)")
        setuid_sgid_files = find_files_with_setuid_setgid()
        report["R56"] = check_compliance("R56", setuid_sgid_files, reference_data)

    # Enregistrement du rapport
    save_yaml_report(report, "gestion_acces_minimal.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    # Affichage des résultats
    print("\n[Résultats de la conformité]")
    for rule, status in report.items():
        print(f"- {rule}: {status['status']}")
        if status["status"] == "Non conforme":
            print(f"  -> Éléments problématiques : {status['elements_detectes']}")
            print(f"  -> Éléments attendus : {status['elements_attendus']}")

    print(f"\nTaux de conformité du niveau minimal (Gestion des accès) : {compliance_percentage:.2f}%")

# R30 - Désactiver les comptes utilisateur inutilisés
def get_standard_users():
    command = "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return set(result.stdout.strip().split("\n"))

def get_active_users():
    who_command = "who | awk '{print $1}'"
    w_command = "w -h | awk '{print $1}'"
    who_result = subprocess.run(who_command, shell=True, capture_output=True, text=True)
    w_result = subprocess.run(w_command, shell=True, capture_output=True, text=True)
    who_users = set(who_result.stdout.strip().split("\n"))
    w_users = set(w_result.stdout.strip().split("\n"))
    return who_users.union(w_users)

def get_recent_users():
    command = "last -n 50 | awk '{print $1}' | sort | uniq"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return set(result.stdout.strip().split("\n"))

def get_inactive_users():
    standard_users = get_standard_users()
    active_users = get_active_users()
    recent_users = get_recent_users()
    inactive_users = standard_users - active_users - recent_users
    return list(inactive_users)

# R53 - Éviter les fichiers ou répertoires sans utilisateur ou sans groupe connu
def find_orphan_files(directory="/"):
    """Recherche les fichiers et répertoires sans utilisateur ni groupe connu."""
    command = f"sudo find {directory} -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        orphan_files = result.stdout.strip().split("\n")
        
        return [file for file in orphan_files if file]  # Supprime les entrées vides
    except subprocess.CalledProcessError as e:
        print(f"[ERREUR] Problème lors de l'exécution de find: {e}")
        return []

# R56 - Éviter l’usage d’exécutables avec les droits spéciaux setuid et setgid
def find_files_with_setuid_setgid():
    command = "find / -type f \\( -perm 6000 \\) -print 2>/dev/null"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    files_with_suid_sgid = result.stdout.strip().split("\n")
    return [file for file in files_with_suid_sgid if file]

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")
