import paramiko
import yaml
import os
import re
from GenerationRapport.GenerationRapport import generate_ssh_html_report

# Dictionary of comments for SSH rules
ssh_comments = {
    "R1": "SSH Protocol version must be 2",
    "R2": "Pubkey Authentication should be enabled",
    "R3": "Password Authentication should be disabled",
    "R4": "Challenge Response Authentication should be disabled",
    "R5": "PermitRootLogin should be disabled",
    "R6": "X11 Forwarding should be disabled",
    "R7": "AllowTcpForwarding should be disabled",
    "R8": "MaxAuthTries should be set to 2",
    "R9": "PermitEmptyPasswords should be disabled",
    "R10": "LoginGraceTime should be set to 30 seconds",
    "R11": "UsePrivilegeSeparation should be sandbox",
    "R12": "AllowUsers must be specified",
    "R13": "AllowGroups must be specified",
    "R14": "Ciphers should be aes256-ctr,aes192-ctr,aes128-ctr",
    "R15": "MACs should be hmac-sha2-512,hmac-sha2-256,hmac-sha1",
    "R16": "PermitUserEnvironment should be disabled",
    "R17": "AllowAgentForwarding should be disabled",
    "R18": "StrictModes should be enabled",
    "R19": "HostKey should be /etc/ssh/ssh_host_rsa_key",
    "R20": "KexAlgorithms should be diffie-hellman-group-exchange-sha256",
    "R21": "AuthorizedKeysFile should be .ssh/authorized_keys",
    "R22": "ClientAliveInterval should be set to 300",
    "R23": "ClientAliveCountMax should be set to 0",
    "R24": "LoginGraceTime should be set to 20",
    "R25": "ListenAddress should be filled with server IP",
    "R26": "Port should be 22"
}

def get_server_users(server):
    """
    Récupère la liste des utilisateurs présents sur le serveur
    avec UID ≥ 1000 (comptes non systèmes).
    """
    try:
        # Utilisation d'awk pour filtrer sur UID ≥ 1000
        stdin, stdout, stderr = server.exec_command("awk -F: '$3>=1000 {print $1}' /etc/passwd")
        return stdout.read().decode().splitlines()
    except Exception as e:
        print(f"Erreur lors de la récupération des utilisateurs : {e}")
        return []

def get_server_groups(server):
    """
    Récupère la liste des groupes présents sur le serveur
    avec GID ≥ 1000 (groupes non systèmes).
    """
    try:
        # Utilisation d'awk pour filtrer sur GID ≥ 1000
        stdin, stdout, stderr = server.exec_command("awk -F: '$3>=1000 {print $1}' /etc/group")
        return stdout.read().decode().splitlines()
    except Exception as e:
        print(f"Erreur lors de la récupération des groupes : {e}")
        return []

def get_server_ip(server):
    """
    Récupère l'adresse IP du serveur via 'hostname -I' et retourne la première adresse.
    """
    try:
        stdin, stdout, stderr = server.exec_command("hostname -I")
        ip_output = stdout.read().decode().strip()
        if ip_output:
            return ip_output.split()[0]
        else:
            return None
    except Exception as e:
        print(f"Erreur lors de la récupération de l'IP du serveur : {e}")
        return None

def update_ssh_criteria_with_system_info(server, file_path="AnalyseConfiguration/Thematiques/criteres_SSH.yaml"):
    """
    Lit le fichier YAML de critères SSH et met à jour directement
    les expected_value pour :
      - R12 (AllowUsers) avec les utilisateurs présents (UID ≥ 1000)
      - R13 (AllowGroups) avec les groupes présents (GID ≥ 1000)
      - R25 (ListenAddress) avec l'IP du serveur récupérée via hostname
    """
    users = get_server_users(server)
    groups = get_server_groups(server)
    server_ip = get_server_ip(server)
    
    # Transformation en chaînes séparées par des virgules
    users_str = ",".join(users)
    groups_str = ",".join(groups)
    
    if not os.path.exists(file_path):
        print(f"Le fichier {file_path} n'existe pas.")
        return
    
    # Lecture du fichier YAML existant
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
    
    if "ssh_criteria" in data:
        if "R12" in data["ssh_criteria"]:
            data["ssh_criteria"]["R12"]["expected_value"] = users_str
        if "R13" in data["ssh_criteria"]:
            data["ssh_criteria"]["R13"]["expected_value"] = groups_str
        if server_ip and "R25" in data["ssh_criteria"]:
            data["ssh_criteria"]["R25"]["expected_value"] = server_ip
    
    # Réécriture du fichier YAML en conservant le style compact (inline)
    with open(file_path, 'w') as f:
        yaml.dump(data, f, default_flow_style=True)
    
    print(f"Les valeurs attendues pour R12, R13 et R25 ont été mises à jour dans {file_path}")

# --- Les fonctions suivantes restent inchangées ---

def generate_yaml_report(all_rules, filename="analyse_ssh.yaml", comments=None):
    try:
        output_dir = "GenerationRapport/RapportAnalyse"
        html_output_dir = "GenerationRapport/RapportAnalyse/RapportHTML"

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(html_output_dir, exist_ok=True)

        yaml_path = os.path.join(output_dir, filename)
        html_path = os.path.join(html_output_dir, filename.replace(".yaml", ".html"))

        total_rules = len(all_rules)
        compliant_rules = sum(1 for rule in all_rules.values() if rule.get("apply", False))
        compliance_percentage = (compliant_rules / total_rules) * 100 if total_rules > 0 else 0

        print(f"SSH compliance: {compliance_percentage:.1f}%")

        with open(yaml_path, "w", encoding="utf-8") as file:
            file.write("# SSH Analysis Report\n")
            file.write("# Change 'apply' to 'true' if you want to apply this recommendation.\n\n")
            file.write("ssh_compliance:\n")

            for rule, details in all_rules.items():
                comment = comments.get(rule, "") if comments else ""
                file.write(f"  {rule}:  # {comment}\n")
                file.write(f"    apply: {'true' if details.get('apply') else 'false'}\n")
                file.write(f"    expected_elements: {details.get('expected_elements')}\n")
                file.write(f"    detected_elements: {details.get('detected_elements')}\n")
                file.write(f"    status: \"{details.get('status')}\"\n")
        print(f"YAML report generated: {yaml_path}")

        # Generate HTML report from YAML
        generate_ssh_html_report(yaml_path, html_path)

    except (OSError, IOError) as e:
        print(f"Error generating the YAML file: {e}")

def check_ssh_configuration_compliance(server, os_info):
    # Mise à jour du fichier de critères avec les infos du serveur (AllowUsers, AllowGroups et ListenAddress)
    update_ssh_criteria_with_system_info(server)
    
    config_data = retrieve_ssh_configuration(server, os_info)
    if config_data is None:
        return
    
    parsed_config = parse_ssh_configuration(config_data)
    compliance_results = check_anssi_compliance(parsed_config)
    
    if compliance_results:
        generate_yaml_report(compliance_results, filename="analyse_ssh.yaml", comments=ssh_comments)
    else:
        print("No compliance data has been generated.")

def convert_time_to_seconds(time_value):
    if time_value.isdigit():
        return int(time_value)
    time_pattern = re.findall(r'(\d+)([hms])', time_value.lower())
    total_seconds = 0
    for value, unit in time_pattern:
        value = int(value)
        if unit == "h":
            total_seconds += value * 3600
        elif unit == "m":
            total_seconds += value * 60
        elif unit == "s":
            total_seconds += value
    return total_seconds

def load_anssi_criteria(file_path="AnalyseConfiguration/Thematiques/criteres_SSH.yaml"):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file {file_path} was not found.")
        with open(file_path, "r") as file:
            data = yaml.safe_load(file)
        if not isinstance(data, dict) or "ssh_criteria" not in data:
            raise ValueError("Invalid YAML file format: missing 'ssh_criteria' section.")
        return data.get("ssh_criteria", {})
    except (yaml.YAMLError, FileNotFoundError, ValueError) as e:
        print(f"Error loading criteria: {e}")
        return {}

def check_anssi_compliance(config):
    anssi_criteria = load_anssi_criteria()
    all_rules = {}
    if not anssi_criteria:
        print("No compliance criteria loaded. Check your YAML file.")
        return {}
    for rule, criteria in anssi_criteria.items():
        directive = criteria.get("directive", "Unknown")
        expected_value = criteria.get("expected_value", "Unknown")
        actual_value = config.get(directive, "not defined")

        if rule == "R1":
            status = "Compliant"
            apply_val = True
            expected = ["Always valid"]
            detected = "Automatically compliant since Ubuntu 20.04 has SSH 2 by default."
        elif directive in ["AllowUsers", "AllowGroups"]:
            if actual_value == "not defined" or actual_value.strip() == "":
                status = f"Non-Compliant -> '{directive}' is empty or undefined, it must be specified."
                apply_val = False
                expected = expected_value.split(",") if isinstance(expected_value, str) else []
                detected = "None"
            else:
                status = f"Compliant -> '{directive}: {actual_value}'"
                apply_val = True
                expected = expected_value.split(",") if isinstance(expected_value, str) else []
                detected = actual_value
        elif directive in ["LoginGraceTime", "ClientAliveInterval"]:
            expected_seconds = convert_time_to_seconds(expected_value)
            actual_seconds = convert_time_to_seconds(actual_value)
            if actual_seconds <= expected_seconds:
                status = f"Compliant -> '{directive}: {actual_value}' | expected: '{directive}: {expected_value}'"
                apply_val = True
                expected = expected_value
                detected = actual_value
            else:
                status = f"Non-Compliant -> '{directive}: {actual_value}' | expected: '{directive}: {expected_value}'"
                apply_val = False
                expected = expected_value
                detected = actual_value
        else:
            apply_val = actual_value == expected_value
            status = f"{'Compliant' if apply_val else 'Non-Compliant'} -> '{directive}: {actual_value}' | expected: '{directive}: {expected_value}'"
            expected = expected_value
            detected = actual_value

        all_rules[rule] = {
            "status": status,
            "apply": apply_val,
            "expected_elements": expected if isinstance(expected, list) else [expected],
            "detected_elements": detected
        }
    return all_rules

def retrieve_ssh_configuration(server, os_info):
    if not isinstance(server, paramiko.SSHClient):
        print("Error: Invalid SSH server.")
        return None
    try:
        if os_info and os_info.get("distro", "").lower() == "ubuntu":
            stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config")
            config_data = stdout.read().decode()
            stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
            extra_config_data = stdout.read().decode()
        else:
            print("Non-Ubuntu OS detected. Attempting alternative SSH configuration retrieval.")
            stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config")
            config_data = stdout.read().decode()
            stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
            extra_config_data = stdout.read().decode()
        
        if not config_data:
            raise ValueError("SSH configuration file is empty or inaccessible.")
        
        full_config = merge_ssh_configurations(config_data, extra_config_data)
        return full_config
    except (paramiko.SSHException, ValueError) as e:
        print(f"Error retrieving SSH configuration: {e}")
        return None

def merge_ssh_configurations(base_config, extra_config):
    parsed_config = parse_ssh_configuration(base_config)
    extra_parsed_config = parse_ssh_configuration(extra_config)
    parsed_config.update(extra_parsed_config)
    merged_config = "\n".join([f"{k} {v}" for k, v in parsed_config.items()])
    return merged_config

def parse_ssh_configuration(config_data):
    parsed_config = {}
    for line in config_data.split("\n"):
        if line.strip() and not line.strip().startswith("#"):
            key_value = line.split(None, 1)
            if len(key_value) == 2:
                parsed_config[key_value[0]] = key_value[1]
    return parsed_config
