import yaml
import os

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

def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie la conformité en fonction de la règle donnée."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    # Comparaison adaptée pour différents types de valeurs attendues
    is_compliant = rule_value == expected_value

    # Gérer ce qui est affiché dans "éléments_detectés"
    detected_elements = rule_value if rule_value else "Aucun"

    compliance_result = {
        "rule_id": rule_id,
        "status": "Conforme" if is_compliant else "Non conforme",
        "appliquer": is_compliant,  # Si conforme, appliquer = True
        "éléments_detectés": detected_elements,
        "éléments_attendus": expected_value
    }

    return compliance_result

# Fonction principale pour analyser les utilisateurs
def analyse_utilisateurs(serveur, niveau, reference_data=None):
    """Analyse les utilisateurs et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml(niveau)

    if niveau == "min":
        print("-> Aucune règle spécifique pour le niveau minimal en gestion des utilisateurs.")

    elif niveau == "moyen":
        print("-> Vérification de l'expiration des sessions (R32)")
        tmout_value = check_tmout(serveur)
        logind_conf = check_logind_conf(serveur)
        report["R32"] = check_compliance("R32", {"TMOUT": tmout_value, "logind_conf": logind_conf}, reference_data)

        print("-> Vérification de la séparation des comptes système et administrateurs (R70)")
        local_users = get_local_users(serveur)
        system_users = get_system_users(serveur)
        admin_users = get_admin_users(serveur)
        ldap_users = check_ldap_users(serveur)
        report["R70"] = check_compliance("R70", {
            "local_users": local_users,
            "system_users": system_users,
            "admin_users": admin_users,
            "ldap_users": ldap_users
        }, reference_data)

    # Enregistrement du rapport
    save_yaml_report(report, f"utilisateurs_{niveau}.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme") if total_rules > 0 else 0
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 100  # 100% si pas de règles

    print(f"\nTaux de conformité du niveau {niveau.upper()} (Utilisateurs) : {compliance_percentage:.2f}%")

# R32 - Vérifier l'expiration des sessions et paramètres logind.conf
def check_tmout(serveur):
    """Vérifie la valeur de TMOUT dans /etc/profile et /etc/bash.bashrc."""
    command_tmout = "grep -E '^TMOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null | awk -F= '{print $2}' | sort -u"
    stdin, stdout, stderr = serveur.exec_command(command_tmout)
    
    # Lire et nettoyer les valeurs
    tmout_values = list(filter(None, stdout.read().decode().strip().split("\n")))

    # Convertir en string pour correspondre à reference_moyen.yaml
    try:
        return str(int(tmout_values[0].strip())) if tmout_values else "Non défini"
    except ValueError:
        return "Non défini"

def check_logind_conf(serveur):
    """Vérifie les paramètres de systemd-logind en excluant les lignes commentées."""
    logind_settings = {
        "IdleAction": "Non défini",
        "IdleActionSec": "Non défini",
        "RuntimeMaxSec": "Non défini"
    }

    command_logind = "sudo grep -E '^(IdleAction|IdleActionSec|RuntimeMaxSec)=' /etc/systemd/logind.conf | grep -v '^#'"
    stdin, stdout, stderr = serveur.exec_command(command_logind)
    
    logind_output = stdout.read().decode().strip().split("\n")

    for line in logind_output:
        if "=" in line:
            key, value = line.strip().split("=", 1)
            if key in logind_settings:
                logind_settings[key] = value.strip()

    # Assurer que les valeurs en secondes sont conformes à reference_moyen.yaml
    for key in ["IdleActionSec", "RuntimeMaxSec"]:
        if logind_settings[key] != "Non défini" and not logind_settings[key].endswith("s"):
            try:
                int_value = int(logind_settings[key])  # Vérifier si c'est un nombre
                logind_settings[key] = f"{int_value}s"  # Ajouter 's' si nécessaire
            except ValueError:
                pass  # Garder la valeur d'origine si elle est déjà une chaîne correcte

    return logind_settings

# R70 - Vérifier la séparation des comptes utilisateurs, système et administrateurs
def get_local_users(serveur):
    """Récupère les utilisateurs locaux définis dans /etc/passwd (UID >= 1000)."""
    command_local_users = "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"
    stdin, stdout, stderr = serveur.exec_command(command_local_users)
    users = sorted(list(filter(None, stdout.read().decode().strip().split("\n"))))  
    return users

def get_system_users(serveur):
    """Récupère les comptes système (UID < 1000)."""
    command_system_users = "awk -F: '$3 < 1000 {print $1}' /etc/passwd"
    stdin, stdout, stderr = serveur.exec_command(command_system_users)
    users = sorted(list(filter(None, stdout.read().decode().strip().split("\n"))))  
    return users

def get_admin_users(serveur):
    """Récupère les utilisateurs appartenant aux groupes sudo ou admin."""
    command_sudo_users = "getent group sudo | awk -F: '{print $4}'"
    stdin, stdout, stderr = serveur.exec_command(command_sudo_users)
    sudo_users = stdout.read().decode().strip().split(",")

    command_admin_users = "getent group admin | awk -F: '{print $4}'"
    stdin, stdout, stderr = serveur.exec_command(command_admin_users)
    admin_users_cmd = stdout.read().decode().strip().split(",")

    admin_users = sorted(list(set(filter(None, sudo_users + admin_users_cmd))))  
    return admin_users

def check_ldap_users(serveur):
    """Vérifie si des utilisateurs administrateurs sont définis dans LDAP."""
    command_ldap_users = "getent passwd | awk -F: '$1 ~ /^ldap/ {print $1}'"
    stdin, stdout, stderr = serveur.exec_command(command_ldap_users)
    ldap_users = sorted(list(filter(None, stdout.read().decode().strip().split("\n"))))  
    return ldap_users

def verify_account_separation(serveur):
    """Vérifie que les comptes système et administrateurs ne sont pas mélangés et retourne les éléments détectés."""
    local_users = get_local_users(serveur)
    system_users = get_system_users(serveur)
    admin_users = get_admin_users(serveur)
    ldap_users = check_ldap_users(serveur)

    # Initialisation du rapport des éléments détectés
    detected_elements = {
        "local_users": local_users,
        "system_users": system_users,
        "admin_users": admin_users,
        "ldap_users": ldap_users
    }

    # Vérifications des incohérences
    issues = []

    # Vérifier si des comptes admin sont aussi des comptes système
    overlapping_admin_system = set(admin_users) & set(system_users)
    if overlapping_admin_system:
        issues.append(f"Comptes admin présents parmi les comptes système : {', '.join(overlapping_admin_system)}")

    # Vérifier si des comptes LDAP sont aussi des comptes système
    overlapping_ldap_system = set(ldap_users) & set(system_users)
    if overlapping_ldap_system:
        issues.append(f"Comptes LDAP présents parmi les comptes système : {', '.join(overlapping_ldap_system)}")

    # Vérifier si des comptes admin sont aussi présents dans LDAP
    overlapping_admin_ldap = set(admin_users) & set(ldap_users)
    if overlapping_admin_ldap:
        issues.append(f"Comptes admin présents dans LDAP : {', '.join(overlapping_admin_ldap)}")

    # Vérifier si des comptes locaux sont administrateurs
    overlapping_local_admin = set(local_users) & set(admin_users)
    if overlapping_local_admin:
        issues.append(f"Comptes locaux ayant des privilèges admin : {', '.join(overlapping_local_admin)}")

    # Retourne les éléments détectés avec une liste vide pour les incohérences si conforme
    return detected_elements, issues


# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")
