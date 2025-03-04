import yaml
import os
import paramiko

# Exécute une commande SSH sur le serveur distant et retourne le résultat
def execute_ssh_command(server, command):
    stdin, stdout, stderr = server.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Vérifie la conformité des règles en comparant les valeurs détectées aux références
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
    
    return {
        "apply": detected_values == expected_values,
        "status": "Conforme" if detected_values == expected_values else "Non-conforme",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }

# Vérifie la configuration IPv4 via sysctl
def check_ipv4_configuration(server):
    command = "sysctl net.ipv4"
    results = {}
    for line in execute_ssh_command(server, command):
        if '=' in line:
            key, value = line.split('=', 1)
            results[key.strip()] = value.strip()
    return results

# Vérifie la configuration de désactivation IPv6 via sysctl
def disable_ipv6(server):
    command = "sysctl -a | grep 'net.ipv6.conf.*.disable_ipv6'"
    result = {}
    for line in execute_ssh_command(server, command):
        if '=' in line:
            key, value = line.split('=', 1)
            result[key.strip()] = value.strip()
    return result

# Liste les services en cours d'exécution
def harden_exposed_services(server):
    command = "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'"
    return {"running_services": execute_ssh_command(server, command)}

# Vérifie certaines règles PAM dans /etc/pam.d/sshd
def secure_remote_authentication_pam(server):
    command = "grep -E '^(auth|account|password|session)' /etc/pam.d/sshd | awk '{$1=$1};1'"
    return {"pam_rules": execute_ssh_command(server, command)}

# Récupère la liste des interfaces réseau et leurs adresses IP
def get_interfaces_with_ips(server):
    command = "ip -o addr show"
    interfaces = {}
    for line in execute_ssh_command(server, command):
        parts = line.split()
        if len(parts) > 3:
            iface = parts[1]
            ip = parts[3].split('/')[0]
            if iface not in interfaces:
                interfaces[iface] = {"ipv4": None, "ipv6": None}
            interfaces[iface]["ipv6" if ':' in ip else "ipv4"] = ip
    return interfaces

# Analyse du réseau et génération du rapport
def analyse_reseau(server, niveau, reference_data=None):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R80": (get_interfaces_with_ips, "Vérification des interfaces réseau avec IP"),
        },
        "moyen": {
            "R12": (check_ipv4_configuration, "Paramétrer les options IPv4"),
            "R13": (disable_ipv6, "Désactiver IPv6"),
            "R79": (harden_exposed_services, "Durcir les services exposés"),
            "R67": (secure_remote_authentication_pam, "Sécuriser l'authentification PAM"),
            "R81": (get_interfaces_with_ips, "Vérification des interfaces restreintes"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, description) in rules[niveau].items():
            print(f"-> Vérification de la règle {rule_id} # {description}")
            detected_values = function(server)
            report[rule_id] = check_compliance(rule_id, detected_values, reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Conforme") / len(report) * 100 if report else 0
    print(f"\nTaux de conformité pour le niveau {niveau.upper()} (Réseau) : {compliance_percentage:.2f}%")

# Sauvegarde le rapport d'analyse dans un fichier YAML
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "a", encoding="utf-8") as file:
        file.write("reseau:\n")
        
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, (None, ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
        file.write("\n")
    
    print(f"Rapport généré : {output_path}")
