import yaml
import os
import paramiko

# Charger les références depuis Reference_Min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_Min.yaml"):
    """Charge le fichier Reference_Min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_Min.yaml : {e}")
        return {}

# Vérification de conformité adaptée pour chaque règle
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie la conformité en fonction de la règle donnée."""
    expected_value = reference_data.get(rule_id, {}).get("expected", [])

    if not isinstance(expected_value, list):
        expected_value = []

    compliance_result = {
        "status": "Conforme" if not rule_value else "Non conforme",
        "appliquer": False if rule_value else True,
    }

    # Adaptation des clés selon la règle
    if rule_id == "R30":
        compliance_result["comptes_inactifs_detectes"] = rule_value if rule_value else "Aucun"
        compliance_result["comptes_attendus"] = expected_value
    elif rule_id == "R53":
        compliance_result["fichiers_orphelins_detectes"] = rule_value if rule_value else "Aucun"
        compliance_result["fichiers_attendus"] = expected_value
    elif rule_id == "R56":
        compliance_result["fichiers_suid_sgid_detectes"] = rule_value if rule_value else "Aucun"
        compliance_result["fichiers_attendus"] = expected_value
    else:
        compliance_result["elements_detectes"] = rule_value if rule_value else "Aucun"
        compliance_result["elements_attendus"] = expected_value

    return compliance_result

# Fonction principale pour analyser la gestion des accès
def analyse_gestion_acces(serveur, niveau="min", reference_data=None):
    """Analyse la gestion des accès et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification de la désactivation des comptes inutilisés (R30)")
        inactive_accounts = get_inactive_users(serveur)
        report["R30"] = check_compliance("R30", inactive_accounts, reference_data)

        print("-> Vérification des fichiers sans propriétaire (R53)")
        orphan_files = find_orphan_files(serveur)
        report["R53"] = check_compliance("R53", orphan_files, reference_data)

        print("-> Vérification des exécutables avec setuid/setgid (R56)")
        setuid_sgid_files = find_files_with_setuid_setgid(serveur)
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
            print(f"  -> Éléments problématiques : {status.get('comptes_inactifs_detectes', 'Aucun')}")
            print(f"  -> Éléments attendus : {status.get('comptes_attendus', 'Aucun')}")

    print(f"\nTaux de conformité du niveau minimal (Gestion des accès) : {compliance_percentage:.2f}%")

# R30 - Désactiver les comptes utilisateur inutilisés
def get_standard_users(serveur):
    """Récupère les utilisateurs standards (UID >= 1000) sur le serveur distant, sauf 'nobody'."""
    command = "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    stdin, stdout, stderr = serveur.exec_command(command)
    return set(filter(None, stdout.read().decode().strip().split("\n")))

def get_recent_users(serveur):
    """Récupère les utilisateurs ayant une connexion récente (moins de 60 jours) sur le serveur distant."""
    command = "lastlog -b 60 | awk 'NR>1 {print $1}' | sort | uniq"
    stdin, stdout, stderr = serveur.exec_command(command)
    return set(filter(None, stdout.read().decode().strip().split("\n")))

def get_disabled_users(serveur):
    """Récupère la liste des comptes désactivés dans /etc/shadow."""
    command = "awk -F: '($2 ~ /^!|^\*/) {print $1}' /etc/shadow"
    stdin, stdout, stderr = serveur.exec_command(command)
    return set(filter(None, stdout.read().decode().strip().split("\n")))

def get_inactive_users(serveur):
    """Récupère la liste des utilisateurs standards qui ne sont ni actifs, ni récemment connectés et qui ne sont pas désactivés."""
    standard_users = get_standard_users(serveur)
    recent_users = get_recent_users(serveur)
    disabled_users = get_disabled_users(serveur)

    # Comptes inactifs depuis plus de 60 jours, excluant les comptes déjà désactivés
    inactive_users = (standard_users - recent_users) - disabled_users

    return list(inactive_users)

# R53 - Éviter les fichiers ou répertoires sans utilisateur ou sans groupe connu
def find_orphan_files(serveur):
    """Recherche les fichiers et répertoires sans utilisateur ni groupe connu sur la machine distante."""
    command = "sudo find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# R56 - Éviter l’usage d’exécutables avec les droits spéciaux setuid et setgid
def find_files_with_setuid_setgid(serveur):
    """Recherche les fichiers avec setuid ou setgid sur la machine distante."""
    command = "find / -type f -perm /6000 -print 2>/dev/null"
    try:
        stdin, stdout, stderr = serveur.exec_command(command)
        files_with_suid_sgid = stdout.read().decode().strip().split("\n")
        return [file for file in files_with_suid_sgid if file]
    except Exception as e:
        print(f"Erreur lors de la récupération des fichiers setuid/setgid : {e}")
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
