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
    """Vérifie la conformité en fonction de la règle donnée et gère le cas particulier de R67."""

    # Charger les valeurs attendues depuis Reference_Moyen.yaml
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    if rule_id == "R67":
        # Construire la liste des éléments attendus sous le même format que les éléments détectés
        expected_list = [f"detected_pam_modules: {expected_value.get('detected_pam_modules', '')}"] + \
                        [f"{module}: {status}" for module, status in expected_value.get("security_modules", {}).items()]

        # Vérifier si tous les éléments détectés correspondent exactement aux valeurs attendues
        is_compliant = set(rule_value) == set(expected_list)

        compliance_result = {
            "rule_id": rule_id,
            "status": "Conforme" if is_compliant else "Non conforme",
            "appliquer": is_compliant,  # Maintenant, appliquer = True si conforme
            "éléments_attendus": expected_value,  # Toujours afficher les éléments attendus
            "éléments_detectés": rule_value if rule_value else []  # Assurer une liste bien formatée
        }
    else:
        # Cas général pour les autres règles
        if not isinstance(expected_value, list):
            expected_value = []

        is_compliant = not rule_value  # Conforme si rule_value est vide

        compliance_result = {
            "rule_id": rule_id,
            "status": "Conforme" if is_compliant else "Non conforme",
            "appliquer": is_compliant,  # Maintenant, appliquer = True si conforme
            "éléments_attendus": expected_value if expected_value else "Non spécifié",
            "éléments_detectés": rule_value if rule_value else []  # Assurer une liste bien formatée
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
        secure_permissions = get_secure_permissions(serveur,reference_data)
        report["R50"] = check_compliance("R50", secure_permissions, reference_data)

        print("-> Vérification des accès aux sockets et pipes nommées (R52)")
        protected_sockets = get_protected_sockets(serveur, reference_data)
        report["R52"] = check_compliance("R52", protected_sockets, reference_data)

        print("-> Vérification de la séparation des répertoires temporaires (R55)")
        user_private_tmp = get_user_private_tmp(serveur)
        report["R55"] = check_compliance("R55", user_private_tmp, reference_data)

        print("-> Vérification de la sécurisation de l'authentification distante via PAM (R67)")
        pam_security = check_pam_security(serveur, reference_data)
        report["R67"] = check_compliance("R67", pam_security, reference_data)

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
    service_accounts = list(filter(None, stdout.read().decode().strip().split("\n")))

    return service_accounts  # Retourne la liste complète des comptes détectés


# R39 - Modifier les directives de configuration sudo
def get_sudo_directives(serveur, reference_data):
    """Vérifie si les directives sudo sont conformes aux recommandations ANSSI en comparant avec Reference_Moyen.yaml."""
    
    # Récupérer les directives attendues depuis Reference_moyen.yaml
    required_directives = set(reference_data.get("R39", {}).get("expected", []))

    # Commande pour récupérer les directives 'Defaults' dans /etc/sudoers
    command = "sudo grep -E '^Defaults' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command)
    detected_directives = set(filter(None, stdout.read().decode().strip().split("\n")))

    return {
        "présentes": list(detected_directives)
    }


# R40 - Utiliser des utilisateurs cibles non-privilégiés pour les commandes sudo
def get_non_privileged_sudo_users(serveur):
    """Vérifie si des utilisateurs ont des privilèges sudo sans restriction (ALL=(ALL) ou ALL=(ALL:ALL))."""
    command = "sudo grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\\(ALL.*\\)' | grep -Ev '(NOPASSWD|%sudo|root)' | awk '{for (i=1; i<NF; i++) if ($i ~ /^ALL=\\(ALL(:ALL)?\\)$/) break; else print $i}'"
    stdin, stdout, stderr = serveur.exec_command(command)
    
    privileged_users = list(filter(None, stdout.read().decode().strip().split("\n")))

    return privileged_users


# R42 - Bannir les négations dans les spécifications sudo
def get_negation_in_sudoers(serveur):
    """Recherche les négations dans sudoers et renvoie une liste des lignes concernées."""
    command = "sudo grep -E '!' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command)

    negation_lines = list(filter(None, stdout.read().decode().strip().split("\n")))

    return negation_lines  # Retourne une liste vide si aucune négation n'est détectée


# R43 - Préciser les arguments dans les spécifications sudo
def get_strict_sudo_arguments(serveur):
    """Vérifie si les règles sudo précisent bien les arguments autorisés et évitent l'usage de wildcard *."""

    # Détecter les règles utilisant un wildcard `*` dans les commandes autorisées
    command_wildcard = "sudo grep -E 'ALL=' /etc/sudoers | grep -E '\\*'"

    # Détecter les règles où les arguments ne sont pas spécifiés après une commande
    command_no_arguments = "sudo grep -E 'ALL=' /etc/sudoers | grep -E 'ALL=[^(]*$'"

    # Détecter les règles incorrectes (mauvaise spécification des arguments)
    command_incorrect_args = (
        "sudo grep -E 'ALL=' /etc/sudoers | "
        "grep -E 'ALL=\\([^)]*\\)[[:space:]]*/[^[:space:]]+[[:space:]]*($|[^\"].*$)' | "
        "grep -Ev '\"\"$|\" [^ ]+\"$'"
    )

    # Exécuter les commandes sur le serveur
    stdin, stdout, stderr = serveur.exec_command(command_wildcard)
    wildcard_issues = set(filter(None, stdout.read().decode().strip().split("\n")))

    stdin, stdout, stderr = serveur.exec_command(command_no_arguments)
    no_argument_issues = set(filter(None, stdout.read().decode().strip().split("\n")))

    stdin, stdout, stderr = serveur.exec_command(command_incorrect_args)
    incorrect_argument_issues = set(filter(None, stdout.read().decode().strip().split("\n")))

    # Fusionner les résultats en supprimant les doublons
    non_compliant_rules = sorted(wildcard_issues | no_argument_issues | incorrect_argument_issues)

    return non_compliant_rules  # Retourne une liste vide si aucune règle non conforme n'est détectée

# R44 - Éditer les fichiers de manière sécurisée avec sudo
def get_sudoedit_usage(serveur):
    """Vérifie si sudoedit est utilisé et si aucun éditeur interdit (vi, nano, etc.) n'est présent dans sudoers."""

    # Vérifier si sudoedit est bien utilisé (bonnes pratiques)
    command_sudoedit = "sudo grep -E 'ALL=.*sudoedit' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command_sudoedit)
    sudoedit_rules = list(filter(None, stdout.read().decode().strip().split("\n")))

    # Vérifier si des éditeurs interdits sont présents (vi, nano, etc.)
    command_bad_editors = "sudo grep -E 'ALL=.*(vi|nano|vim|emacs)' /etc/sudoers"
    stdin, stdout, stderr = serveur.exec_command(command_bad_editors)
    bad_editor_rules = list(filter(None, stdout.read().decode().strip().split("\n")))

    # Si sudoedit est présent et aucun éditeur interdit n'est trouvé, alors c'est conforme
    if sudoedit_rules and not bad_editor_rules:
        return []  # Conforme, donc retourne une liste vide

    # Si sudoedit est absent, on ajoute un message expliquant la non-conformité
    if not sudoedit_rules:
        bad_editor_rules.append("sudoedit non trouvé dans /etc/sudoers")

    return bad_editor_rules  # Retourne uniquement les problèmes détectés


# R50 - Restreindre les droits d’accès aux fichiers et aux répertoires sensibles
def get_secure_permissions(serveur, reference_data):
    """Vérifie les permissions des fichiers sensibles et retourne les fichiers non conformes."""

    # Charger les permissions attendues depuis Reference_Moyen.yaml
    expected_permissions = reference_data.get("R50", {}).get("expected", {}).get("secure_permissions", [])

    # Transformer la liste en dictionnaire pour une comparaison facile
    expected_dict = {entry.split(" ")[0]: entry.split(" ")[1] for entry in expected_permissions}

    # Liste des fichiers à vérifier
    files_to_check = list(expected_dict.keys())

    # Exécuter la commande `stat` pour obtenir les permissions des fichiers
    command = f"sudo stat -c '%a %n' {' '.join(files_to_check)} 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip().split("\n")

    # Reformater la sortie pour correspondre au format attendu (fichier permission)
    detected_permissions = {line.split(" ")[1]: line.split(" ")[0] for line in output if line}

    # Vérifier la conformité des permissions
    non_compliant = [
        f"{file} {detected_permissions[file]}"
        for file in detected_permissions
        if detected_permissions[file] != expected_dict.get(file, "")
    ]

    return non_compliant if non_compliant else []  # Retourne une liste des fichiers non conformes, ou vide si conforme


# R52 - Restreindre les accès aux sockets et aux pipes nommées
def get_protected_sockets(serveur, reference_data):
    """Vérifie que les sockets et pipes nommées sont bien protégées avec les permissions appropriées."""

    # Charger les sockets attendues depuis Reference_Moyen.yaml
    expected_sockets = set(reference_data.get("R52", {}).get("expected", {}).get("protected_sockets", []))

    # Exécuter la commande `ss -xp` pour lister les sockets UNIX détectées sur la machine
    command_list_sockets = "sudo ss -xp | awk '{print $5}' | cut -d':' -f1 | sort -u"
    stdin, stdout, stderr = serveur.exec_command(command_list_sockets)
    detected_sockets = set(filter(None, stdout.read().decode().strip().split("\n")))

    # Conserver uniquement les sockets attendues **qui existent réellement** sur le système
    relevant_sockets = expected_sockets.intersection(detected_sockets)

    # Vérifier les permissions des sockets détectées
    if relevant_sockets:
        command_check_permissions = f"sudo ls -l {' '.join(relevant_sockets)} 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command_check_permissions)
        socket_permissions = stdout.read().decode().strip().split("\n")
    else:
        socket_permissions = []

    # Reformater la sortie pour avoir `{socket: permissions}`
    detected_permissions = {line.split()[-1]: line.split()[0] for line in socket_permissions if line}

    # Vérifier la conformité des permissions (ne doivent pas être 777 ou 666)
    non_compliant_sockets = [
        f"{socket} - permissions incorrectes: {detected_permissions.get(socket, 'Absente')}"
        for socket in relevant_sockets
        if detected_permissions.get(socket, "").startswith(("srwxrwxrwx", "srw-rw-rw-"))  # Trop permissif
    ]

    # Ajouter les sockets détectées mais absentes de la liste de référence
    unexpected_sockets = detected_sockets - expected_sockets
    if unexpected_sockets:
        non_compliant_sockets.append(f"Sockets non référencées détectées: {', '.join(unexpected_sockets)}")

    return non_compliant_sockets if non_compliant_sockets else []  # Liste des sockets non conformes ou vide si tout est OK

# R55 - Séparer les répertoires temporaires des utilisateurs
def get_user_private_tmp(serveur):
    """Vérifie que les répertoires temporaires des utilisateurs sont bien séparés et sécurisés."""

    issues_detected = []

    # Vérifier si `/tmp` est monté avec les options `noexec` et `nodev`
    command_tmp_mount = "mount | grep ' /tmp '"
    stdin, stdout, stderr = serveur.exec_command(command_tmp_mount)
    tmp_mount_options = stdout.read().decode().strip()
    if "noexec" not in tmp_mount_options or "nodev" not in tmp_mount_options:
        issues_detected.append(f"Options incorrectes pour /tmp : {tmp_mount_options}")

    # Vérifier la présence de `pam_namespace` et `pam_mktemp`
    command_pam_check = "grep -E 'pam_namespace|pam_mktemp' /etc/pam.d/common-session"
    stdin, stdout, stderr = serveur.exec_command(command_pam_check)
    pam_config = stdout.read().decode().strip()
    if not pam_config:
        issues_detected.append("Les modules PAM `pam_namespace` ou `pam_mktemp` ne sont pas activés.")

    # Vérifier les fichiers modifiables par tout le monde
    command_world_writable = "sudo find / -type f -perm -0002 -ls 2>/dev/null | head -n 10"
    stdin, stdout, stderr = serveur.exec_command(command_world_writable)
    world_writable_files = stdout.read().decode().strip().split("\n")
    
    if world_writable_files and world_writable_files[0]:  # S'il y a au moins un fichier détecté
        issues_detected.append("Fichiers modifiables par tout le monde détectés :")
        issues_detected.extend(world_writable_files)

    return issues_detected if issues_detected else []  # Retourne une liste des problèmes ou vide si conforme

# R67 - Sécuriser les authentifications distantes par PAM
def check_pam_security(serveur, reference_data):
    """Vérifie si l'authentification à distance via PAM est sécurisée (R67)."""

    # Charger les valeurs attendues depuis Reference_Moyen.yaml
    expected_values = reference_data.get("R67", {}).get("expected", {})

    # Vérifier l'utilisation du module d'authentification distant (pam_ldap attendu)
    command_pam_auth = "grep -Ei 'pam_ldap' /etc/pam.d/* 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command_pam_auth)
    detected_pam_entries = stdout.read().decode().strip().split("\n")

    # Si pam_ldap est détecté, l'afficher, sinon "Non trouvé"
    detected_pam_module = "pam_ldap" if detected_pam_entries and any("pam_ldap" in line for line in detected_pam_entries) else "Non trouvé"

    # Vérifier la présence des modules de sécurité requis
    security_modules = expected_values.get("security_modules", {})
    detected_security_modules = {}

    for module in security_modules.keys():
        command = f"grep -E '{module}' /etc/pam.d/* 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_status = "Enabled" if stdout.read().decode().strip() else "Non trouvé"
        
        # Stocker la valeur détectée
        detected_security_modules[module] = detected_status

    # Construire les éléments détectés
    detected_elements = {
        "detected_pam_modules": detected_pam_module,
        "security_modules": detected_security_modules
    }

    # Construire la liste des éléments détectés (inclut tous les éléments attendus)
    detected_list = []

    # Ajouter les modules PAM LDAP
    detected_list.append(f"detected_pam_modules: {detected_elements['detected_pam_modules']}")

    # Ajouter les modules de sécurité PAM
    for module, detected_status in detected_elements["security_modules"].items():
        detected_list.append(f"{module}: {detected_status}")

    return detected_list


# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")