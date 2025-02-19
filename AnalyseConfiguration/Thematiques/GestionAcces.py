import yaml
import os
import paramiko

# Exécute une commande SSH sur le serveur distant et retourne le résultat
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Vérifie la conformité des règles en comparant avec les références
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", [])
    expected_values = expected_values if isinstance(expected_values, list) else []

    return {
        "appliquer": False if detected_values else True,
        "status": "Conforme" if not detected_values else "Non conforme",
        "éléments_attendus": expected_values,
        "éléments_detectés": detected_values or "Aucun"
    }

# Récupère les utilisateurs standards (UID >= 1000) sauf 'nobody'
def get_standard_users(serveur):
    return set(execute_ssh_command(serveur, "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"))

# Récupère les utilisateurs ayant une connexion récente (moins de 60 jours)
def get_recent_users(serveur):
    return set(execute_ssh_command(serveur, "last -s -60days -F | awk '{print $1}' | grep -v 'wtmp' | sort | uniq"))

# Récupère la liste des comptes désactivés dans /etc/shadow
def get_disabled_users(serveur):
    return set(execute_ssh_command(serveur, "awk -F: '($2 ~ /^!|^\\*/) {print $1}' /etc/shadow"))

# Récupère la liste des utilisateurs inactifs
def get_inactive_users(serveur):
    return list((get_standard_users(serveur) - get_recent_users(serveur)) - get_disabled_users(serveur))

# Recherche les fichiers et répertoires sans utilisateur ni groupe
def find_orphan_files(serveur):
    return execute_ssh_command(serveur, "sudo find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null")

# Recherche les exécutables avec les droits spéciaux setuid et setgid
def find_files_with_setuid_setgid(serveur):
    return execute_ssh_command(serveur, "find / -type f -perm /6000 -print 2>/dev/null")

# Récupère la liste des comptes de service
def get_service_accounts(serveur):
    return execute_ssh_command(serveur, "awk -F: '($3 < 1000) && ($1 != \"root\") {print $1}' /etc/passwd")

# Analyse la gestion des accès et génère un rapport
def analyse_gestion_acces(serveur, niveau, reference_data):
    report = {}
    
    rules = {
        "min": {
            "R30": (get_inactive_users, "Désactiver les comptes utilisateur inutilisés"),
            "R53": (find_orphan_files, "Éviter les fichiers ou répertoires sans utilisateur ou groupe connu"),
            "R56": (find_files_with_setuid_setgid, "Limiter les exécutables avec setuid/setgid"),
        },
        "moyen": {
            "R34": (get_service_accounts, "Désactiver les comptes de service non utilisés"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Vérification de la règle {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    
    save_yaml_report(report, f"gestion_acces_{niveau}.yml", rules)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Conforme") / len(report) * 100 if report else 0
    print(f"\nTaux de conformité du niveau {niveau.upper()} : {compliance_percentage:.2f}%")

# Enregistre le rapport d'analyse au format YAML avec commentaires
def save_yaml_report(data, output_file, rules):
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "w", encoding="utf-8") as file:
        for rule_id, content in data.items():
            comment = rules["min"].get(rule_id, (None, ""))[1] or rules["moyen"].get(rule_id, (None, ""))[1]
            file.write(f"{rule_id}:  # {comment}\n")
            yaml.dump(content, file, default_flow_style=False, allow_unicode=True, indent=2)
    
    print(f"Rapport généré : {output_path}")
