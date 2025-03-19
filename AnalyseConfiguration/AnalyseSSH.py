import paramiko
import yaml
import os
import re
from GenerationRapport.GenerationRapport import generate_ssh_html_report

#-------------MAIN FUNCTION-----------------#

# Orchestrates the retrieval, analysis, and compliance check of the SSH configuration.
# Retrieves the SSH configuration (with OS check), parses it, checks compliance against ANSSI criteria,
# and generates a YAML report if compliance results are available.
def check_ssh_configuration_compliance(server, os_info):
    config_data = retrieve_ssh_configuration(server, os_info)
    if config_data is None:
        return
    
    parsed_config = parse_ssh_configuration(config_data)
    compliance_results = check_anssi_compliance(parsed_config)
    
    if compliance_results:
        generate_yaml_report(compliance_results)
    else:
        print("No compliance data has been generated.")

# Converts an SSH time value (e.g., '2m', '30s', '1h30m') into seconds.
def convert_time_to_seconds(time_value):
    if time_value.isdigit():
        return int(time_value)  # Case where it is already a number in seconds

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

#-------------UTILITY FUNCTIONS-----------------#

# Loads ANSSI compliance criteria from a YAML file and returns a dictionary of criteria.
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

# Executes a list of commands on the server via SSH.
# For Ubuntu, commands are executed normally.
# For other distributions, an alternative behavior is defined.
def execute_ssh_commands(server, commands, os_info):
    if not isinstance(server, paramiko.SSHClient):
        print("Error: Invalid SSH connection.")
        return
    
    try:
        for command in commands:
            if os_info and os_info.get("distro", "").lower() == "ubuntu":
                # Ubuntu block: execute the command normally.
                stdin, stdout, stderr = server.exec_command(command)
                stdout.read().decode()
                stderr.read().decode()
            else:
                # Other distro block: define alternative behavior.
                distro = os_info.get("distro", "unknown") if os_info else "unknown"
                print(f"Command '{command}' skipped: unsupported OS ({distro}).")
    except paramiko.SSHException as e:
        print(f"SSH error when executing commands: {e}")

# Generates a YAML report on SSH compliance based on the provided rules.
# Creates output directories, writes the YAML report, and then generates an HTML report.
def generate_yaml_report(all_rules, filename="analyse_ssh.yaml"):
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
            file.write("# SSH Analysis Report: ---\n")
            file.write("# Change 'apply' to 'true' if you want to apply this recommendation.\n\n\n")
            file.write("ssh_compliance:\n")

            for rule, details in all_rules.items():
                status = details.get("status", "Unknown")
                apply_val = details.get("apply", False)
                expected = details.get("expected_elements", [])
                detected = details.get("detected_elements", "Not defined")

                file.write(f"  {rule}:\n")
                file.write(f"    apply: {'true' if apply_val else 'false'}\n")
                file.write(f"    expected_elements: {expected}\n")
                file.write(f"    detected_elements: {detected}\n")
                file.write(f"    status: \"{status}\"\n")

        print(f"YAML report generated: {yaml_path}")

        generate_ssh_html_report(yaml_path, html_path)

    except (OSError, IOError) as e:
        print(f"Error generating the YAML file: {e}")

# Checks SSH configuration compliance against ANSSI criteria.
# Returns a dictionary containing rules with their status and compliance details.
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

        # Rule 1 is always valid
        if rule == "R1":
            status = "Compliant"
            apply_val = True
            expected = ["Always valid"]
            detected = "Automatically compliant since Ubuntu 20.04 has SSH 2 by default."
        # Special check for AllowUsers and AllowGroups (must be filled)
        elif directive in ["AllowUsers", "AllowGroups"]:
            if actual_value == "not defined" or actual_value.strip() == "":
                status = f"Non-Compliant -> '{directive}' is empty or undefined, it must be specified."
                apply_val = False
                expected = criteria.get("expected_value", [])
                detected = "None"
            else:
                status = f"Compliant -> '{directive}: {actual_value}'"
                apply_val = True
                expected = criteria.get("expected_value", [])
                detected = actual_value
        # Special comparison for time values (e.g., LoginGraceTime)
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
        # Standard comparison for other directives
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

# Retrieves the SSH configuration from the server.
# For Ubuntu, standard command execution is used.
# For other distributions, an alternative retrieval method is applied.
def retrieve_ssh_configuration(server, os_info):
    if not isinstance(server, paramiko.SSHClient):
        print("Error: Invalid SSH server.")
        return None
    try:
        if os_info and os_info.get("distro", "").lower() == "ubuntu":
            # Ubuntu block: execute standard commands.
            stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config")
            config_data = stdout.read().decode()
            
            stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
            extra_config_data = stdout.read().decode()
        else:
            # Other distro block: alternative retrieval method.
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

# Merges the base SSH configuration with additional configuration files.
# Returns the merged configuration as a string.
def merge_ssh_configurations(base_config, extra_config):
    parsed_config = parse_ssh_configuration(base_config)
    extra_parsed_config = parse_ssh_configuration(extra_config)
    
    parsed_config.update(extra_parsed_config)
    merged_config = "\n".join([f"{k} {v}" for k, v in parsed_config.items()])
    return merged_config

# Parses the SSH configuration file and returns a dictionary of configuration options.
def parse_ssh_configuration(config_data):
    parsed_config = {}
    for line in config_data.split("\n"):
        if line.strip() and not line.strip().startswith("#"):
            key_value = line.split(None, 1)
            if len(key_value) == 2:
                parsed_config[key_value[0]] = key_value[1]
    return parsed_config
