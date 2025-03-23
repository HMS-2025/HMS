import yaml
import paramiko

def load_yaml(yaml_file):
    """Charger un fichier YAML en UTF-8."""
    with open(yaml_file, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

def save_yaml(yaml_file, config):
    """Sauvegarder la configuration dans un fichier YAML en UTF-8."""
    with open(yaml_file, 'w', encoding='utf-8') as file:
        yaml.safe_dump(config, file, default_flow_style=False, allow_unicode=True)

def apply_command(command, client):
    """Exécute une commande via le client SSH et retourne True en cas de succès."""
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        if error:
            print(f"Erreur lors de l'exécution de la commande : {error}")
            return False
        return True
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande : {e}")
        return False
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

# Get list of non-system users (UID >= 1000) excluding "nobody"
def get_server_users(server):
    # Retrieve users with UID >= 1000, excluding "nobody"
    try:
        stdin, stdout, stderr = server.exec_command("awk -F: '$3>=1000 {print $1}' /etc/passwd")
        users = stdout.read().decode().splitlines()
        return [user for user in users if user != "nobody"]
    except Exception as e:
        print(f"Error retrieving users: {e}")
        return []

# Get list of non-system groups (GID >= 1000) excluding "nogroup"
def get_server_groups(server):
    # Retrieve groups with GID >= 1000, excluding "nogroup"
    try:
        stdin, stdout, stderr = server.exec_command("awk -F: '$3>=1000 {print $1}' /etc/group")
        groups = stdout.read().decode().splitlines()
        return [group for group in groups if group != "nogroup"]
    except Exception as e:
        print(f"Error retrieving groups: {e}")
        return []

# Get the server IP address using 'hostname -I'
def get_server_ip(server):
    # Retrieve server IP address (first one from hostname -I)
    try:
        stdin, stdout, stderr = server.exec_command("hostname -I")
        ip_output = stdout.read().decode().strip()
        if ip_output:
            return ip_output.split()[0]
        else:
            return None
    except Exception as e:
        print(f"Error retrieving server IP: {e}")
        return None

# List directives and their file paths from /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf.
# The last occurrence (in processing order) is considered effective.
def list_directives_with_paths(client):
    directives_map = {}
    main_file = "/etc/ssh/sshd_config"
    # Process main configuration file
    try:
        stdin, stdout, stderr = client.exec_command(f"cat {main_file}")
        main_content = stdout.read().decode()
        for line in main_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                directive, value = parts
                directives_map[directive] = (value, main_file)
    except Exception as e:
        print(f"Error reading {main_file}: {e}")
    
    # Process additional configuration files in sshd_config.d/
    try:
        stdin, stdout, stderr = client.exec_command("ls /etc/ssh/sshd_config.d/*.conf")
        files_list = stdout.read().decode().splitlines()
        for file_path in files_list:
            try:
                stdin, stdout, stderr = client.exec_command(f"cat {file_path}")
                content = stdout.read().decode()
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        directive, value = parts
                        directives_map[directive] = (value, file_path)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
    except Exception as e:
        print(f"Error listing /etc/ssh/sshd_config.d/*.conf: {e}")
    
    return directives_map

# Update the SSH criteria YAML file with system info (AllowUsers, AllowGroups, ListenAddress)
def update_ssh_criteria_with_system_info(server, file_path="AnalyseConfiguration/Thematiques/criteres_SSH.yaml"):
    # Update expected_value for R12, R13, and R25 based on system info.
    # NOTE: Modify the expected_value in ssh_criteria as per your desired configuration
    # because this file will be used for the application.
    users = get_server_users(server)
    groups = get_server_groups(server)
    server_ip = get_server_ip(server)
    
    # Convert lists to comma-separated strings
    users_str = ",".join(users)
    groups_str = ",".join(groups)
    
    if not os.path.exists(file_path):
        print(f"The file {file_path} does not exist.")
        return
    
    # Read existing YAML file
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
    
    if "ssh_criteria" in data:
        if "R12" in data["ssh_criteria"]:
            data["ssh_criteria"]["R12"]["expected_value"] = users_str
        if "R13" in data["ssh_criteria"]:
            data["ssh_criteria"]["R13"]["expected_value"] = groups_str
        if server_ip and "R25" in data["ssh_criteria"]:
            data["ssh_criteria"]["R25"]["expected_value"] = server_ip
    
    # Write the YAML file in block style (proper indentation)
    with open(file_path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    print(f"The expected values for R12, R13, and R25 have been updated in {file_path}.")
    print("Reminder: Please modify the expected_value in ssh_criteria according to your desired configuration, as this file will be used for the application.")

# Generate a YAML report based on compliance rules
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
            file.write("# Change 'apply' to 'true' if you want to apply this recommendation.\n")
            file.write("# Reminder: Modify the expected_value in ssh_criteria as per your configuration requirements, as this file will be used by the application.\n\n")
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

# Apply selected SSH recommendations by updating the SSH configuration based on the analysis file.
# For each rule, the corresponding directive is updated in the file where it is defined.
# The last occurrence (in files /etc/ssh/sshd_config.d/ or /etc/ssh/sshd_config) is considered effective.
def apply_selected_recommendationsSSH(yaml_file, client):
    """
    Apply selected SSH recommendations by updating the SSH configuration based on the analysis file.
    For each rule, the corresponding directive is updated in the file where it is defined.
    The last occurrence (in files /etc/ssh/sshd_config.d/ or /etc/ssh/sshd_config) is considered effective.
    """
    # Backup the sshd_config file if not already backed up
    backup_command = "test -f /etc/ssh/sshd_config.back || sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.back"
    if apply_command(backup_command, client):
        print("sshd_config backup created (or already exists).")
    else:
        print("Error creating sshd_config backup.")
    
    # Load the analysis file
    config = load_yaml(yaml_file)
    # Accept either 'ssh_conformite' or 'ssh_compliance'
    rules = config.get("ssh_conformite") or config.get("ssh_compliance")
    if not rules:
        print("No compliance data found in the analysis file.")
        return
    
    # Load SSH criteria from the criteria file
    criteria_file = "AnalyseConfiguration/Thematiques/criteres_SSH.yaml"
    criteria_data = load_yaml(criteria_file)
    ssh_criteria = criteria_data.get("ssh_criteria", {})
    if not ssh_criteria:
        print("No SSH criteria found in the criteria file.")
        return
    
    # Retrieve the mapping of directives and their file paths.
    directives_map = list_directives_with_paths(client)
    
    # For each rule in the analysis file, update the SSH configuration in the file where the directive is defined.
    for rule, details in rules.items():
        if rule not in ssh_criteria:
            print(f"Rule {rule} not found in criteria file. Skipping.")
            continue
        
        directive = ssh_criteria[rule].get("directive")
        expected_value = ssh_criteria[rule].get("expected_value")
        
        if not directive or expected_value is None:
            print(f"Missing directive or expected value for rule {rule}.")
            continue
        
        # Replace commas with spaces for AllowUsers and AllowGroups
        if directive in ["AllowUsers", "AllowGroups"]:
            expected_value = expected_value.replace(",", " ")
        
        # Determine the file path to update:
        # If the directive is found in the mapping, use its file; otherwise, default to /etc/ssh/sshd_config.
        file_path = directives_map.get(directive, (None, "/etc/ssh/sshd_config"))[1]
        
        # Build the sed command to update the directive in the determined file
        command = f"sudo sed -i '/^#\\?\\s*{directive}/c\\{directive} {expected_value}' {file_path}"
        print(f"Applying rule {rule}: updating '{directive}' to '{expected_value}' in {file_path}")
        if apply_command(command, client):
            details["apply"] = True
            details["status"] = "Compliant"
            print(f"Rule {rule} applied successfully.")
        else:
            details["status"] = "Non compliant"
            print(f"Failed to apply rule {rule}.")
    
    # Restart the SSH service to apply changes
    if apply_command("sudo systemctl restart ssh", client):
        print("SSH service restarted successfully.")
    else:
        print("Error restarting SSH service.")
    
    # Update and save the analysis file
    config["ssh_conformite"] = rules
    save_yaml(yaml_file, config)

# Convert time value (e.g., '30s', '1h') to seconds
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

# Load ANSSI criteria from YAML file
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

# Check compliance of SSH configuration against ANSSI criteria
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

# Retrieve SSH configuration from server by merging /etc/ssh/sshd_config and files in sshd_config.d/
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

# Merge base and extra SSH configurations into one string
def merge_ssh_configurations(base_config, extra_config):
    parsed_config = parse_ssh_configuration(base_config)
    extra_parsed_config = parse_ssh_configuration(extra_config)
    parsed_config.update(extra_parsed_config)
    merged_config = "\n".join([f"{k} {v}" for k, v in parsed_config.items()])
    return merged_config

# Parse SSH configuration into a dictionary
def parse_ssh_configuration(config_data):
    parsed_config = {}
    for line in config_data.split("\n"):
        if line.strip() and not line.strip().startswith("#"):
            key_value = line.split(None, 1)
            if len(key_value) == 2:
                parsed_config[key_value[0]] = key_value[1]
    return parsed_config
