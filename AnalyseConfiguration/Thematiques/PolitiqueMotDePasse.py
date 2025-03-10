import paramiko
import yaml
import os
from GenerationRapport.GenerationRapport import generate_html_report

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

# Comparer les résultats de l'analyse avec les références
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si une règle est conforme en la comparant avec Reference_min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    non_compliant_items = {}
    detected_items = {}

    # Toujours inclure les valeurs détectées dans detected_items
    for key, detected in rule_value.items():
        detected_items[key] = detected  # Ajout des éléments détectés sans condition

    # Comparer chaque sous-règle avec les valeurs attendues
    for key, expected in expected_value.items():
        detected = rule_value.get(key, "Non détecté")

        # Gestion spécifique pour empty_passwords : Comparaison de listes
        if isinstance(expected, list) and isinstance(detected, list):
            if set(detected) != set(expected):
                non_compliant_items[key] = {
                    "detected": detected,
                    "expected": expected
                }
        elif detected != expected:
            if key == 'faillock':
                result = check_faillock_compliance(detected, expected)
                if result:
                    non_compliant_items[key] = result
            elif key == 'expiration_policy':
                result = check_expiration_policy_compliance(detected, expected)
                if result:
                    non_compliant_items[key] = result
            else:
                non_compliant_items[key] = {"detected": detected, "expected": expected}

    return {
        "apply": False if non_compliant_items else True,
        "status": "Non-conforme" if non_compliant_items else "Conforme",
        "detected_elements": detected_items,  # Contient toutes les valeurs détectées
        "expected_elements": expected_value  # Conserve expected dans une section distincte
    }

def check_faillock_compliance (detected , expected) : 
    detected = int(detected)
    expected = int(expected)
    if detected <= expected : 
        return {}
    return {"detected": detected,"expected": expected}
    
def check_expiration_policy_compliance (detected , expected) : 
    detected = int(detected)
    expected = int(expected)
    if detected <= expected : 
        return {}
    return {"detected": detected,"expected": expected}

# Fonction principale pour analyser la politique de mot de passe
def analyse_politique_mdp(serveur, niveau, reference_data=None):
    """Analyse la politique de mot de passe et génère un rapport YAML avec conformité."""
    report = {
        "password": {}
    }

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification de la politique de mot de passe (R31)")
        password_policy = get_password_policy(serveur)
        report["password"]["R31"] = check_compliance("R31", password_policy, reference_data)

        # Vérification de la protection des mots de passe stockés (R68)
        print("-> Vérification de la protection des mots de passe stockés (R68)")
        password_protection = get_stored_passwords_protection(serveur)
        report["password"]["R68"] = check_compliance("R68", password_protection, reference_data)

    elif niveau == "moyen":
        print("-> Aucune règle définie pour le niveau moyen.")
        compliance_percentage = 100.00
        print(f"\nTaux de conformité du niveau {niveau} (Politique de mot de passe) : {compliance_percentage:.2f}%")
        return

    # Enregistrement du rapport
    save_yaml_report(report, f"analyse_{niveau}.yml")
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    # Calcul du taux de conformité
    total_rules = len(report["password"])
    conforming_rules = sum(1 for result in report["password"].values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau {niveau} (Politique de mot de passe) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
    
# R31 - Vérifier la politique de mot de passe
def get_password_policy(serveur):
    """Analyse la politique de mots de passe du système."""
    policy_data = {}

    # 1. Vérifier la politique de mot de passe dans PAM (Normalisation de la sortie)
    pam_policy_raw = execute_remote_command(
        serveur, "sudo grep -E 'pam_pwquality.so|pam_unix.so' /etc/pam.d/common-password",
        "Détecté", "Aucune politique PAM détectée"
    )
    
    if pam_policy_raw != "Aucune politique PAM détectée":
        # Suppression des tabulations et espaces superflus pour normaliser la sortie
        pam_policy_cleaned = " ".join(pam_policy_raw.split())
        policy_data["pam_policy"] = pam_policy_cleaned
    else:
        policy_data["pam_policy"] = "Non détecté"

    # 2. Vérifier l'expiration des mots de passe avec `chage`
    expiration_policy_raw = execute_remote_command(
        serveur, "sudo chage -l $(whoami) | awk -F': ' '/Maximum number of days between password change/ {print $2}'",
        "Détecté", "-1"
    )

    # Conversion en int si possible pour éviter les guillemets
    try:
        policy_data["expiration_policy"] = int(expiration_policy_raw.strip())
    except ValueError:
        policy_data["expiration_policy"] = -1

    # 3. Vérifier si faillock est activé
    faillock_raw = execute_remote_command(
        serveur, "sudo grep '^deny\\s*=' /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' '",
        "Détecté", "-1"
    )

    # Conversion en int si possible pour éviter les guillemets
    try:
        policy_data["faillock"] = int(faillock_raw.strip())
    except ValueError:
        policy_data["faillock"] = -1

    return policy_data


# R68 - Vérifier la protection des mots de passe stockés
def get_stored_passwords_protection(serveur):
    """Analyse la sécurité des mots de passe stockés dans /etc/shadow en vérifiant les permissions,
    la présence de mots de passe hachés et la configuration de l'algorithme de hachage."""
    password_protection_status = {}

    # 1. Vérifier les permissions de /etc/shadow
    password_protection_status["shadow_permissions"] = execute_remote_command(
        serveur, "ls -l /etc/shadow | awk '{print $1, $3, $4}'",
        "Détecté", "Permissions introuvables"
    )

    # 2. Vérifier la présence de mots de passe hachés
    hashed_passwords = execute_remote_command(
        serveur, "sudo grep -E '^[^:]+:[!$]' /etc/shadow | wc -l",
        "Oui", "Non"
    )
    password_protection_status["hashed_passwords"] = "Oui" if hashed_passwords != "Non" else "Non"

    # 3. Vérifier la présence de mots de passe en clair
    password_protection_status["cleartext_passwords"] = execute_remote_command(
        serveur, "sudo grep -E '^[^:]+:[^!$*]' /etc/shadow",
        "Oui (Risque détecté)", "Non"
    )

    # 4. Vérifier si des comptes ont des mots de passe vides
    empty_passwords = execute_remote_command(
        serveur, "sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow",
        "Détecté", "Aucun"
    )
    password_protection_status["empty_passwords"] = empty_passwords.split("\n") if empty_passwords != "Aucun" else []

    # 5. Vérifier les algorithmes de hachage utilisés dans /etc/shadow
    detected_hashes = execute_remote_command(
        serveur, "sudo awk -F':' '{print $2}' /etc/shadow | grep -E '^\$[0-9a-zA-Z]+\$' | cut -d'$' -f2 | sort -u",
        "Non détecté", "Non détecté"
    )
    password_protection_status["hash_algorithms"] = detected_hashes.split("\n") if detected_hashes != "Non détecté" else ["Non détecté"]
    
    return password_protection_status

# Exécute une commande sur le serveur distant et retourne un état standardisé
def execute_remote_command(serveur, command, expected_output, default_output):
    """Exécute une commande distante et normalise la sortie."""
    try:
        stdin, stdout, stderr = serveur.exec_command(command)
        output = stdout.read().decode().strip()
        return output if output else default_output
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande : {command} -> {e}")
        return default_output

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True , indent=4, sort_keys=False)

    print(f"Rapport généré : {output_path}")
