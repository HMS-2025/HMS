import yaml
import os
import paramiko

def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path}: {e}")
        return {}

def execute_ssh_command(server, command):
    try:
        stdin, stdout, stderr = server.exec_command(command)
        output = stdout.read().decode().strip().split("\n")
        return [line for line in output if line]
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande SSH: {command} - {e}")
        return []

def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", [])
    expected_values = expected_values if isinstance(expected_values, list) else []
    
    return {
        "apply": bool(detected_values),
        "status": "Non-conforme",
        "expected_elements": expected_values,
        "detected_elements": detected_values or "Aucun"
    }

def check_grub_password(server, reference_data):
    command_check_grub_cfg = "grep -E 'set\\s+superusers' /etc/grub.d/* /boot/grub/grub.cfg"
    command_check_password = "grep -E 'password_pbkdf2' /etc/grub.d/* /boot/grub/grub.cfg"
    
    superusers_output = execute_ssh_command(server, command_check_grub_cfg)
    password_output = execute_ssh_command(server, command_check_password)
    
    if superusers_output or password_output:
        return {
            "apply": True,
            "status": "Conforme",
            "detected_elements": superusers_output + password_output
        }
    else:
        return {
            "apply": False,
            "status": "Non-conforme",
            "detected_elements": "Aucun"
        }

def get_installed_packages(server):
    return execute_ssh_command(server, "dpkg --get-selections | grep -v deinstall")

def check_installed_packages(server, reference_data):
    expected_packages = reference_data.get("R58", {}).get("expected", [])
    installed_packages = get_installed_packages(server)
    unnecessary_packages = [pkg.split()[0] for pkg in installed_packages if pkg.split()[0] not in expected_packages]
    
    return {
        "apply": bool(unnecessary_packages),
        "status": "Non-conforme" if unnecessary_packages else "Conforme",
        "detected_elements": unnecessary_packages or "Aucun"
    }

def get_trusted_repositories(server, reference_data):
    return execute_ssh_command(server, "grep -E '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null")

def analyse_maintenance(server, niveau, reference_data):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R58": (check_installed_packages, "Installer uniquement les paquets strictement nécessaires"),
            "R59": (get_trusted_repositories, "Utiliser des dépôts de paquets de confiance"),
        },
        "moyen": {
            "R5": (check_grub_password, "Assurer qu'un mot de passe GRUB 2 est configuré"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Vérification de la règle {rule_id} # {comment}")
            detected_values = function(server, reference_data)
    
            if isinstance(detected_values, list):  
                report[rule_id] = {
                    "apply": bool(detected_values),
                    "status": "Non-conforme" if detected_values else "Conforme",
                    "detected_elements": detected_values or "Aucun"
                }
            else:
                report[rule_id] = detected_values
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    compliance_percentage = (
        sum(1 for r in report.values() if isinstance(r, dict) and r.get("status") == "Conforme") 
        / len(report) * 100
    ) if report else 0
    print(f"\nTaux de conformité pour le niveau {niveau.upper()} (Maintenance): {compliance_percentage:.2f}%")

def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("maintenance:\n")
        
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n") 
        file.write("\n")
    
    print(f"Rapport généré: {output_path}")
