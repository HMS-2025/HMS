import yaml
import os
import paramiko

# Exécute une commande SSH et retourne la sortie sous forme de liste

def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Vérification de la conformité des règles
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = expected_values if isinstance(expected_values, list) else list(expected_values.values())
    
    return {
        "apply": set(detected_values) == set(expected_values_list),
        "status": "Conforme" if set(detected_values) == set(expected_values_list) else "Non-conforme",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }

# Extraction des informations système
def get_password_policy(serveur):
    return execute_ssh_command(serveur, "sudo grep -E 'pam_pwquality.so|pam_unix.so' /etc/pam.d/common-password")

def get_stored_passwords_protection(serveur):
    return execute_ssh_command(serveur, "ls -l /etc/shadow")

# Chargement du fichier de référence
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"Erreur lors du chargement du fichier de référence : {e}")
        return {}

# Analyse et génération du rapport YAML
def analyse_politique_mdp(serveur, niveau, reference_data=None):
    if reference_data is None:
        reference_data = load_reference_yaml()
    
    report = {}
    rules = {
        "min": {
            "R31": (get_password_policy, "Vérification de la politique de mot de passe")
        },
        "moyen": {
            "R68": (get_stored_passwords_protection, "Vérification de la protection des mots de passe stockés")
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> {comment} ({rule_id})")
            report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    
    compliance_percentage = sum(1 for result in report.values() if result["status"] == "Conforme") / len(report) * 100 if report else 0
    print(f"\nTaux de conformité du niveau {niveau.upper()} : {compliance_percentage:.2f}%")

# Enregistrement du rapport YAML
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "a", encoding="utf-8") as file:
        file.write("mdp:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False)
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
        file.write("\n")
    
    print(f"Rapport généré : {output_path}")
