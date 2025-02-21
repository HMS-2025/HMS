import yaml
import os

# Execute an SSH command on the remote server and return the result
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Charger les références depuis Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}

# Comparer les résultats de l'analyse avec les références
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = []
    
    if isinstance(expected_values, dict):
        for key, value in expected_values.items():
            if isinstance(value, list):
                expected_values_list.extend(value)
            else:
                expected_values_list.append(value)
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    
    status = "Compliant" if detected_values == "active" else "Non-compliant"
    if detected_values == "Not Installed":
        status = "Not Installed"
    elif detected_values == "inactive":
        status = "Installed but Inactive"
    
    return {
        "apply": set(detected_values) == set(expected_values),
        "status": "Conforme" if set(detected_values) == set(expected_values) else "Non-conforme",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }
# Fonctions spécifiques aux règles de journalisation
def get_audit_log_status(serveur):
    result = execute_ssh_command(serveur, "systemctl is-active auditd")
    if not result:
        return "Not Installed"
    if "inactive" in result:
        return "inactive"
    if "active" in result:
        return "active"
    return "Unknown"

def get_log_rotation(serveur):
    return execute_ssh_command(serveur, "cat /etc/logrotate.conf | grep rotate") if get_audit_log_status(serveur) != "Not Installed" else None

def get_auditd_configuration(serveur):
    return execute_ssh_command(serveur, "auditctl -l") if get_audit_log_status(serveur) != "Not Installed" else None

def get_admin_command_logging(serveur):
    return execute_ssh_command(serveur, "grep -E 'execve' /etc/audit/audit.rules") if get_audit_log_status(serveur) != "Not Installed" else None

def get_audit_log_protection(serveur):
    return execute_ssh_command(serveur, "ls -l /var/log/audit/") if get_audit_log_status(serveur) != "Not Installed" else None

def check_r33(serveur):
    audit_status = get_audit_log_status(serveur)
    return {
        "audit_log_status": audit_status,
        "auditd_configuration": get_auditd_configuration(serveur) if audit_status != "Not Installed" else None,
        "admin_command_logging": get_admin_command_logging(serveur) if audit_status != "Not Installed" else None,
        "audit_log_protection": get_audit_log_protection(serveur) if audit_status != "Not Installed" else None,
        "log_rotation": get_log_rotation(serveur) if audit_status != "Not Installed" else None
    }

# Fonction principale pour analyser la journalisation et l'audit
def analyse_journalisation(serveur, niveau="min", reference_data=None):
    if reference_data is None:
        reference_data = load_reference_yaml()
    
    report = {}
    rules = {
        "min": {},
        "moyen": {
            "R33": (check_r33, "Ensure accountability of administrative actions")
        },
        "avancé": {}
    }
    
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in logging and auditing.")
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    
    compliance_percentage = (sum(1 for result in report.values() if result["status"] == "Compliant") / len(report) * 100) if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (Logging / Audit) : {compliance_percentage:.2f}%")

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("journalisation:\n")
        
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False)
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
    
    print(f"Report generated: {output_path}")
