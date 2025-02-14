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

# Vérification de conformité adaptée pour chaque règle
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie la conformité en fonction de la règle donnée."""
    expected_value = reference_data.get(rule_id, {}).get("expected", [])

    if not isinstance(expected_value, list):
        expected_value = []

    compliance_result = {
        "rule_id": rule_id,
        "status": "Conforme" if not rule_value else "Non conforme",
        "appliquer": False if rule_value else True,
        "éléments_detectés": rule_value if rule_value else "Aucun",
        "éléments_attendus": expected_value
    }

    return compliance_result

# Fonction principale pour analyser la gestion des accès
def analyse_gestion_acces(serveur, niveau, reference_data=None):
    """Analyse la gestion des accès et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml(niveau)

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

    elif niveau == "moyen":
        print("-> Vérification de la désactivation des comptes de service (R34)")
        service_accounts = get_service_accounts(serveur)
        report["R34"] = check_compliance("R34", service_accounts, reference_data)

        print("-> Vérification des directives sudo (R39)")
        sudo_directives = get_sudo_directives(serveur,reference_data)
        report["R39"] = check_compliance("R39", sudo_directives, reference_data)

        print("-> Vérification des utilisateurs cibles non-privilégiés pour sudo (R40)")
        non_privileged_users = get_non_privileged_sudo_users(serveur)
        report["R40"] = check_compliance("R40", non_privileged_users, reference_data)

        print("-> Vérification des négations dans sudoers (R42)")
        negation_in_sudo = get_negation_in_sudoers(serveur)
        report["R42"] = check_compliance("R42", negation_in_sudo, reference_data)

        print("-> Vérification de la précision des arguments dans sudoers (R43)")
        strict_sudo_arguments = get_strict_sudo_arguments(serveur)
        report["R43"] = check_compliance("R43", strict_sudo_arguments, reference_data)

        print("-> Vérification de l'utilisation de sudoedit (R44)")
        sudoedit_usage = get_sudoedit_usage(serveur)
        report["R44"] = check_compliance("R44", sudoedit_usage, reference_data)

        print("-> Vérification des droits d'accès aux fichiers sensibles (R50)")
        secure_permissions = get_secure_permissions(serveur)
        report["R50"] = check_compliance("R50", secure_permissions, reference_data)

        print("-> Vérification des accès aux sockets et pipes nommées (R52)")
        protected_sockets = get_protected_sockets(serveur)
        report["R52"] = check_compliance("R52", protected_sockets, reference_data)

        print("-> Vérification de la séparation des répertoires temporaires (R55)")
        user_private_tmp = get_user_private_tmp(serveur)
        report["R55"] = check_compliance("R55", user_private_tmp, reference_data)

    # Enregistrement du rapport
    save_yaml_report(report, f"gestion_acces_{niveau}.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau {niveau.upper()} (Gestion des accès) : {compliance_percentage:.2f}%")

# R30 - Désactiver les comptes utilisateur inutilisés
def get_standard_users(serveur):
    """Récupère les utilisateurs standards (UID >= 1000) sur le serveur distant, sauf 'nobody'."""
    command = "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    stdin, stdout, stderr = serveur.exec_command(command)
    return set(filter(None, stdout.read().decode().strip().split("\n")))

def get_recent_users(serveur):
    """Récupère les utilisateurs ayant une connexion récente (moins de 60 jours) sur le serveur distant."""
    command = "last -s -60days -F | awk '{print $1}' | grep -v 'wtmp' | sort | uniq"
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
    
# Fonctions pour récupérer les données des règles de niveau moyen

# R34 - Désactiver les comptes de service
def get_service_accounts(serveur):
    """Récupère la liste des comptes de service actifs."""
    command = "awk -F: '($3 < 1000) && ($1 != \"root\") {print $1}' /etc/passwd"
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# R39 - Modifier les directives de configuration sudo
def get_sudo_directives(serveur, reference_data):
    """Vérifie si les directives sudo sont conformes aux recommandations ANSSI en comparant avec Reference_Moyen.yaml."""
    
    # Récupérer la liste des directives attendues depuis Reference_moyen.yaml
    required_directives = set(reference_data.get("R39", {}).get("expected", []))

    # Commande pour récupérer les directives 'Defaults' dans /etc/sudoers
    command = "grep -E '^Defaults' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command)

    # Récupérer les directives détectées
    detected_directives = set(filter(None, stdout.read().decode().strip().split("\n")))

    return {
        "présentes": list(detected_directives),
        "manquantes": list(required_directives - detected_directives)
    }

# R40 - Utiliser des utilisateurs cibles non-privilégiés pour les commandes sudo
def get_non_privileged_sudo_users(serveur):
    """Vérifie si des utilisateurs ont des privilèges sudo sans restriction (ALL=(ALL) ou ALL=(ALL:ALL))."""
    command = "grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\\(ALL.*\\)' | grep -Ev '(NOPASSWD|%sudo|root)' | awk '{for (i=1; i<NF; i++) if ($i ~ /^ALL=\\(ALL(:ALL)?\\)$/) break; else print $i}'"
    
    stdin, stdout, stderr = serveur.exec_command(command)
    
    # Liste des utilisateurs détectés ayant accès root via sudo
    privileged_users = list(filter(None, stdout.read().decode().strip().split("\n")))

    return privileged_users  # Renvoie une liste des utilisateurs problématiques



# a partir de R42 j'ai pas vérifié encore-------------------------------------------
# R42 - Bannir les négations dans les spécifications sudo
def get_negation_in_sudoers(serveur):
    """Recherche les négations dans sudoers."""
    command = "grep -E '!' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command)
    return stdout.read().decode().strip()

# R43 - Préciser les arguments dans les spécifications sudo
def get_strict_sudo_arguments(serveur):
    """Vérifie si les règles sudo précisent bien les arguments autorisés."""
    command = "grep -E 'ALL=' /etc/sudoers | grep -E '\\*'"
    stdin, stdout, stderr = serveur.exec_command(command)
    return stdout.read().decode().strip()

# R44 - Éditer les fichiers de manière sécurisée avec sudo
def get_sudoedit_usage(serveur):
    """Vérifie si sudoedit est utilisé pour l'édition sécurisée des fichiers."""
    command = "grep -E 'ALL=.*vi|ALL=.*nano' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command)
    return stdout.read().decode().strip()

# R50 - Restreindre les droits d’accès aux fichiers et aux répertoires sensibles
def get_secure_permissions(serveur):
    """Vérifie les permissions des fichiers sensibles."""
    command = "stat -c '%a %n' /etc/shadow /etc/passwd /etc/group /etc/gshadow /etc/ssh/sshd_config"
    stdin, stdout, stderr = serveur.exec_command(command)
    return stdout.read().decode().strip().split("\n")

# R52 - Restreindre les accès aux sockets et aux pipes nommées
def get_protected_sockets(serveur):
    """Récupère la liste des sockets et pipes nommées protégées."""
    command = "ss -xp"
    stdin, stdout, stderr = serveur.exec_command(command)
    return stdout.read().decode().strip().split("\n")

# R55 - Séparer les répertoires temporaires des utilisateurs
def get_user_private_tmp(serveur):
    """Vérifie la séparation des répertoires temporaires des utilisateurs."""
    command = "mount | grep '/tmp'"
    stdin, stdout, stderr = serveur.exec_command(command)
    return stdout.read().decode().strip()

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")