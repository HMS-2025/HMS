import yaml
import paramiko
import os
import re
from datetime import datetime
from GenerationRapport.GenerationRapport import generate_ssh_html_report

# Log an action with a timestamp in the journal file located in GenerationRapport/RapportAnalyse
def log_action(action):
    # Log an action with a timestamp in the journal file
    log_dir = os.path.join("GenerationRapport", "RapportAnalyse")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "journalisation.txt")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} - {action}\n")

# Execute a command on the server via the SSH client and log it
def exec_command_logged(client, command):
    # Execute a command on the server via SSH and log it
    log_action(f"Executing command: {command}")
    return client.exec_command(command)

# Load a YAML file and return its contents
def load_yaml(yaml_file):
    # Load a YAML file
    with open(yaml_file, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

# Save a configuration to a YAML file
def save_yaml(yaml_file, config):
    # Save a configuration to a YAML file
    with open(yaml_file, 'w', encoding='utf-8') as file:
        yaml.safe_dump(config, file, default_flow_style=False, allow_unicode=True)

# Create or update a backup of the specified file (saved as file_path.back)
def backup_file(file_path, client):
    # Create or update a backup of the specified file so that the backup reflects the initial state at each run
    backup_path = f"{file_path}.back"
    backup_command = f"sudo cp {file_path} {backup_path}"
    if apply_command(backup_command, client):
        log_action(f"Backup updated for {file_path} as {backup_path}.")
        return True
    else:
        log_action(f"Failed to update backup for {file_path}.")
        return False

# Execute a command via the SSH client, log it, and return True if successful
def apply_command(command, client):
    # Execute a command via SSH, log its output and errors, and return True if it succeeds
    try:
        stdin, stdout, stderr = exec_command_logged(client, command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            print(f"Error executing command: {error}")
            log_action(f"Error executing command: {error}")
            return False
        if output:
            log_action(f"Command output: {output}")
        return True
    except Exception as e:
        print(f"Error executing command: {e}")
        log_action(f"Error executing command: {e}")
        return False

# SSH compliance rules descriptions
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

# Retrieve for each directive the file containing its last occurrence by reading the main file and included files
def list_directives_with_paths(client):
    # Retrieve directives and their corresponding file paths from the SSH configuration
    last_directive_file = {}
    main_file = "/etc/ssh/sshd_config"
    include_patterns = []
    try:
        stdin, stdout, stderr = exec_command_logged(client, f"cat {main_file}")
        main_content = stdout.read().decode()
        for line in main_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("include"):
                parts = line.split()
                if len(parts) >= 2:
                    for pattern in parts[1:]:
                        include_patterns.append(pattern)
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                directive, value = parts
                last_directive_file[directive] = main_file
    except Exception as e:
        print(f"Error reading {main_file}: {e}")
        log_action(f"Error reading {main_file}: {e}")

    for pattern in include_patterns:
        try:
            ls_command = f"ls {pattern}"
            stdin, stdout, stderr = exec_command_logged(client, ls_command)
            files_list = sorted(stdout.read().decode().splitlines())
            for file_path in files_list:
                try:
                    stdin, stdout, stderr = exec_command_logged(client, f"cat {file_path}")
                    content = stdout.read().decode()
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            directive, value = parts
                            last_directive_file[directive] = file_path
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    log_action(f"Error reading {file_path}: {e}")
        except Exception as e:
            print(f"Error listing files for pattern {pattern}: {e}")
            log_action(f"Error listing files for pattern {pattern}: {e}")

    return last_directive_file

# Load and return ANSSI criteria from the specified YAML file
def load_anssi_criteria(file_path="AnalyseConfiguration/Thematiques/criteres_SSH.yaml"):
    # Load ANSSI criteria from the YAML file
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file {file_path} was not found.")
        with open(file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
        if not isinstance(data, dict) or "ssh_criteria" not in data:
            raise ValueError("Invalid YAML file format: missing 'ssh_criteria' section.")
        return data.get("ssh_criteria", {})
    except (yaml.YAMLError, FileNotFoundError, ValueError) as e:
        print(f"Error loading criteria: {e}")
        log_action(f"Error loading criteria: {e}")
        return {}

# Parse SSH configuration content into a dictionary
def parse_ssh_configuration(config_data):
    # Parse SSH configuration content into a dictionary
    parsed_config = {}
    for line in config_data.split("\n"):
        if line.strip() and not line.strip().startswith("#"):
            key_value = line.split(None, 1)
            if len(key_value) == 2:
                parsed_config[key_value[0]] = key_value[1]
    return parsed_config

# Apply SSH recommendations based on the compliance YAML file, create backups, and prepare rollback
def apply_selected_recommendationsSSH(yaml_file, client):
    # Apply SSH recommendations based on the compliance YAML file.
    # Create systematic backups of the main SSH configuration and all included files, then prepare a rollback plan and update the configuration.
    if backup_file("/etc/ssh/sshd_config", client):
        print("sshd_config backup updated.")
        log_action("sshd_config backup updated.")
    else:
        print("Error updating sshd_config backup.")
        log_action("Error updating sshd_config backup.")
        return

    tmp_config_path = "/tmp/sshd_config.new"
    rollback_flag_path = "/tmp/backup_flag"

    # Create the rollback flag
    apply_command(f"sudo touch {rollback_flag_path}", client)
    log_action(f"Rollback flag created at {rollback_flag_path}.")

    # Retrieve files containing current directives and build the set of files to be backed up (including the main file)
    directives_map = list_directives_with_paths(client)
    files_to_backup = set(directives_map.values())
    files_to_backup.add("/etc/ssh/sshd_config")

    # Create systematic backups of all files that will be modified
    for file_path in files_to_backup:
        backup_file(file_path, client)

    # Build the rollback plan to restore all backups and restart SSH
    rollback_cmds = []
    for file_path in files_to_backup:
        rollback_cmds.append(f"sudo cp {file_path}.back {file_path}")
    rollback_cmds.append("sudo systemctl restart ssh")
    full_rollback_command = f"if [ -f {rollback_flag_path} ]; then " + " && ".join(rollback_cmds) + "; fi"

    # Schedule an automatic rollback (2 minutes) if configuration validation fails
    combined_command = f"echo \"{full_rollback_command}\" | at now + 2 minutes 2>/dev/null"
    apply_command(combined_command, client)
    print("Rollback plan scheduled with the 'at' command (persists after reboot).")
    log_action("Rollback plan scheduled with the 'at' command (persists after reboot).")

    # Verify scheduled 'at' jobs
    stdin, stdout, stderr = exec_command_logged(client, "atq")
    atq_output = stdout.read().decode().strip()
    if atq_output:
        print("At jobs scheduled successfully:")
        print(atq_output)
        log_action(f"At queue:\n{atq_output}")
    else:
        print("No at jobs found; please check your 'at' configuration.")
        log_action("No at jobs found; please check your 'at' configuration.")

    # Load compliance configuration
    config = load_yaml(yaml_file)
    rules = config.get("ssh_compliance")
    if not rules:
        print("No compliance data found in the analysis file (ssh_compliance).")
        log_action("No compliance data found in the analysis file (ssh_compliance).")
        return

    # Load SSH criteria (ANSSI)
    criteria_file = "AnalyseConfiguration/Thematiques/criteres_SSH.yaml"
    ssh_criteria = load_anssi_criteria(criteria_file)
    if not ssh_criteria:
        print("No SSH criteria found in the criteria file.")
        log_action("No SSH criteria found in the criteria file.")
        return

    # Copy the main configuration file to a temporary file for modification
    if not apply_command(f"sudo cp /etc/ssh/sshd_config {tmp_config_path}", client):
        print("Error copying the SSH configuration.")
        log_action("Error copying the SSH configuration.")
        return

    # Remove the UsePrivilegeSeparation directive from the temporary file
    apply_command(f"sudo sed -i '/^#\\?\\s*UsePrivilegeSeparation/d' {tmp_config_path}", client)

    modified_main_config = False
    multi_valued_directives = ["AllowUsers", "AllowGroups", "Ciphers", "MACs"]

    # Process rules R1 to R26
    for i in range(1, 27):
        rule = f"R{i}"
        if rule in ["R1", "R11"]:
            print(f"Rule {rule} removed from application (not applicable as per requirements).")
            log_action(f"Rule {rule} removed from application (not applicable).")
            continue

        details = rules.get(rule)
        if not details:
            print(f"Rule {rule} not present in the YAML.")
            log_action(f"Rule {rule} not present in the YAML.")
            continue

        apply_value = details.get("apply", False)
        if isinstance(apply_value, str):
            try:
                apply_bool = yaml.safe_load(apply_value.lower())
            except Exception:
                apply_bool = False
        else:
            apply_bool = bool(apply_value)

        if not apply_bool:
            print(f"Rule {rule} ignored because 'apply' is false.")
            log_action(f"Rule {rule} ignored because 'apply' is false.")
            continue

        if rule not in ssh_criteria:
            print(f"Rule {rule} missing from SSH criteria.")
            log_action(f"Rule {rule} missing from SSH criteria.")
            continue

        directive = ssh_criteria[rule].get("directive")
        expected_value = ssh_criteria[rule].get("expected_value")
        if not directive or expected_value is None:
            print(f"Missing directive or expected value for rule {rule}.")
            log_action(f"Missing directive or expected value for rule {rule}.")
            continue

        if isinstance(expected_value, list):
            expected_value = " ".join(expected_value)
        if directive in ["AllowUsers", "AllowGroups"]:
            expected_value = expected_value.replace(",", " ")

        effective_file = directives_map.get(directive, None)
        if effective_file is None:
            effective_file = tmp_config_path
            modified_main_config = True
            file_origin = "main file (temporary)"
        else:
            file_origin = f"associated file {effective_file}"

        if directive in multi_valued_directives:
            delete_command = f"sudo sed -i '/^#\\?\\s*{directive}\\b/d' {effective_file}"
            if apply_command(delete_command, client):
                print(f"Occurrences of {directive} have been removed in {file_origin}.")
                log_action(f"Occurrences of {directive} removed in {file_origin}.")
            else:
                print(f"Error removing {directive} in {file_origin}.")
                log_action(f"Error removing {directive} in {file_origin}.")
                details["status"] = "Non compliant"
                continue

            append_command = f"echo '{directive} {expected_value}' | sudo tee -a {effective_file} >/dev/null"
            if apply_command(append_command, client):
                details["status"] = "Compliant"
                print(f"Rule {rule} successfully applied in {file_origin} (directive {directive} reset).")
                log_action(f"Rule {rule} successfully applied in {file_origin}.")
            else:
                details["status"] = "Non compliant"
                print(f"Failed to apply rule {rule} for {directive} in {file_origin}.")
                log_action(f"Failed to apply rule {rule} for {directive} in {file_origin}.")
        else:
            command = f"sudo sed -i '/^#\\?\\s*{directive}\\b/c\\{directive} {expected_value}' {effective_file}"
            print(f"Applying rule {rule} on {file_origin}: updating '{directive}' to '{expected_value}'")
            log_action(f"Applying rule {rule} on {file_origin}: updating '{directive}' to '{expected_value}'")
            if apply_command(command, client):
                check_command = f"grep -q '^{directive}\\b' {effective_file}"
                stdin, stdout, stderr = exec_command_logged(client, check_command)
                if stdout.channel.recv_exit_status() != 0:
                    append_command = f"echo '{directive} {expected_value}' | sudo tee -a {effective_file} >/dev/null"
                    apply_command(append_command, client)
                    print(f"{directive} added in {file_origin} as it did not exist.")
                    log_action(f"{directive} added in {file_origin} as it did not exist.")
                details["status"] = "Compliant"
                print(f"Rule {rule} successfully applied in {file_origin}.")
                log_action(f"Rule {rule} successfully applied in {file_origin}.")
            else:
                details["status"] = "Non compliant"
                print(f"Failed to apply rule {rule} in {file_origin}.")
                log_action(f"Failed to apply rule {rule} in {file_origin}.")

    # If the main file was modified using the temporary file, validate and apply changes
    if modified_main_config:
        print("Validating temporary SSH configuration...")
        log_action("Validating temporary SSH configuration...")
        stdin, stdout, stderr = exec_command_logged(client, f"sudo sshd -t -f {tmp_config_path}")
        error = stderr.read().decode()
        if error:
            print(f"Invalid configuration: {error}\nRollback will be triggered automatically.")
            log_action(f"Invalid configuration: {error} - Rollback will be triggered.")
            return

        print("Valid configuration. Applying changes to the main file.")
        log_action("Valid configuration. Applying changes to the main file.")
        if apply_command(f"sudo mv {tmp_config_path} /etc/ssh/sshd_config", client):
            user_input = input("Do you want to restart the SSH service now? [y/N] : ").strip().lower()
            if user_input == 'y':
                if apply_command("sudo systemctl restart ssh", client):
                    apply_command(f"sudo rm -f {rollback_flag_path}", client)
                    print("SSH service restarted successfully. Rollback flag removed.")
                    log_action("SSH service restarted successfully. Rollback flag removed.")
                    # Remove scheduled at jobs
                    stdin, stdout, stderr = exec_command_logged(client, "atq")
                    atq_output = stdout.read().decode().strip()
                    if atq_output:
                        for line in atq_output.splitlines():
                            job_id = line.split()[0]
                            apply_command(f"atrm {job_id}", client)
                            log_action(f"Removed at job {job_id}.")
                else:
                    print("Failed to restart the SSH service. Rollback will be executed.")
                    log_action("Failed to restart SSH service. Rollback will be executed.")
            else:
                print("SSH restart cancelled by the user. The scheduled rollback will be executed if necessary.")
                log_action("SSH restart cancelled by the user. Rollback scheduled if necessary.")
        else:
            print("Error updating the main SSH file.")
            log_action("Error updating the main SSH file.")
    else:
        user_input = input("Do you want to restart the SSH service now? [y/N] : ").strip().lower()
        if user_input == 'y':
            if apply_command("sudo systemctl restart ssh", client):
                apply_command(f"sudo rm -f {rollback_flag_path}", client)
                print("SSH service restarted successfully. Rollback flag removed.")
                log_action("SSH service restarted successfully. Rollback flag removed.")
                # Remove scheduled at jobs
                stdin, stdout, stderr = exec_command_logged(client, "atq")
                atq_output = stdout.read().decode().strip()
                if atq_output:
                    for line in atq_output.splitlines():
                        job_id = line.split()[0]
                        apply_command(f"atrm {job_id}", client)
                        log_action(f"Removed at job {job_id}.")
            else:
                print("Failed to restart the SSH service. Rollback will be executed.")
                log_action("Failed to restart SSH service. Rollback will be executed.")
        else:
            print("SSH restart cancelled by the user. The scheduled rollback will be executed if necessary.")
            log_action("SSH restart cancelled by the user. Rollback scheduled if necessary.")
