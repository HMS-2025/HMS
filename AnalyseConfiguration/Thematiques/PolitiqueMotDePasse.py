import paramiko
import yaml
import os

# R31 - Utiliser des mots de passe robustes
# Vérifier la politique de mot de passe (PAM, pwquality, expiration, faillock)
def analyse_politique_mdp(serveur, niveau="min"):
    """Analyse la politique de mot de passe et génère un rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Vérification de la politique de mot de passe (R31)")
        report["password_policy"] = get_password_policy(serveur)
    
    save_yaml_report(report, "politique_mdp_minimal.yml")
    print("Analyse terminée. Rapport généré : politique_mdp_minimal.yml")

def get_password_policy(serveur):
    try:
        policy_data = {}

        # 1. Vérifier la politique de mot de passe dans PAM
        command_pam = "grep -E 'pam_pwquality.so|pam_unix.so' /etc/pam.d/common-password"
        stdin, stdout, stderr = serveur.exec_command(command_pam)
        policy_data["PAM Policy"] = stdout.read().decode().strip() or "Aucune politique PAM détectée"

        # 2. Vérifier l'expiration des mots de passe avec chage
        command_expiration = "chage -l $(whoami)"
        stdin, stdout, stderr = serveur.exec_command(command_expiration)
        policy_data["Expiration Policy"] = stdout.read().decode().strip() or "Expiration non définie"

        # 3. Vérifier si faillock est activé
        command_faillock = "grep 'deny' /etc/security/faillock.conf 2>/dev/null || grep 'pam_faillock.so' /etc/pam.d/*"
        stdin, stdout, stderr = serveur.exec_command(command_faillock)
        policy_data["Faillock"] = stdout.read().decode().strip() or "Faillock non configuré"

        # 4. Vérifier la configuration de pwquality.so
        command_pwquality = "cat /etc/security/pwquality.conf 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command_pwquality)
        policy_data["Pwquality Config"] = stdout.read().decode().strip() or "Fichier pwquality.conf non trouvé"

        return policy_data
    except Exception as e:
        print(f"Erreur lors de la récupération de la politique de mot de passe : {e}")
        return {}

# R68 - Protéger les mots de passe stockés
def get_stored_passwords_protection(serveur):
    try:
        password_protection_status = {}

        # 1. Vérifier si /etc/shadow est bien utilisé et a des permissions restrictives
        command_shadow = "sudo ls -l /etc/shadow 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command_shadow)
        shadow_output = stdout.read().decode().strip()
        password_protection_status["/etc/shadow Permissions"] = shadow_output or "Fichier /etc/shadow introuvable"

        # 2. Vérifier si les mots de passe sont hachés dans /etc/shadow
        command_hashes = "sudo grep -E '^[^:]+:[!$]' /etc/shadow | wc -l"
        stdin, stdout, stderr = serveur.exec_command(command_hashes)
        hashed_passwords_count = stdout.read().decode().strip()
        password_protection_status["Mots de passe hachés"] = "Oui" if int(hashed_passwords_count) > 0 else "Non"

        # 3. Vérifier si des mots de passe sont stockés en clair (cas anormal)
        command_cleartext = "sudo grep -E '^[^:]+:[^!$*]' /etc/shadow"
        stdin, stdout, stderr = serveur.exec_command(command_cleartext)
        cleartext_output = stdout.read().decode().strip()
        password_protection_status["Présence de mots de passe en clair"] = "Oui (Risque détecté)" if cleartext_output else "Non"

        # 4. Vérifier si des comptes ont des mots de passe vides (risque de sécurité)
        command_empty_passwords = "sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow"
        stdin, stdout, stderr = serveur.exec_command(command_empty_passwords)
        empty_passwords = stdout.read().decode().strip()
        password_protection_status["Comptes avec mot de passe vide"] = empty_passwords if empty_passwords else "Aucun"

        # 5. Vérifier les algorithmes de hachage utilisés dans /etc/shadow (SHA-512 recommandé, Argon2, scrypt, PBKDF2)
        command_hash_type = "sudo grep -oP '\\\$[1-6a]\\\$' /etc/shadow | sort -u"
        stdin, stdout, stderr = serveur.exec_command(command_hash_type)
        hash_types = stdout.read().decode().strip()
        password_protection_status["Algorithmes de hachage détectés"] = hash_types if hash_types else "Aucun hachage détecté"

        # 6. Vérifier si Argon2, scrypt ou PBKDF2 sont utilisés
        command_memory_hard = "sudo grep -E '\\\$argon2|\\\$scrypt|\\\$pbkdf2' /etc/shadow"
        stdin, stdout, stderr = serveur.exec_command(command_memory_hard)
        memory_hard_algos = stdout.read().decode().strip()
        password_protection_status["Utilisation de fonctions de dérivation memory-hard"] = memory_hard_algos if memory_hard_algos else "Non détecté"

        return password_protection_status
    except Exception as e:
        print(f"Erreur lors de la vérification de la protection des mots de passe : {e}")
        return {}

def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    # Définir le chemin du dossier de sortie
    output_dir = "GenerationRapport/RapportAnalyse"
    
    # S'assurer que le dossier existe
    os.makedirs(output_dir, exist_ok=True)
    
    # Construire le chemin complet du fichier de sortie
    output_path = os.path.join(output_dir, output_file)
    
    # Écriture des données dans le fichier YAML
    with open(output_path, "w") as file:
        yaml.dump(data, file, default_flow_style=False)
    
    print(f"Rapport généré : {output_path}")