import paramiko
import yaml
import os
from GenerationRapport.GenerationRapport import generate_html_report

# Load references from Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    """Load the Reference_min.yaml file and return its content."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Error loading Reference_min.yaml: {e}")
        return {}

# Compare analysis results with references
def check_compliance(rule_id, rule_value, reference_data):
    """Check if a rule is compliant by comparing it with Reference_min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    non_compliant_items = {}
    detected_items = {}

    # Always include detected values in detected_items
    for key, detected in rule_value.items():
        detected_items[key] = detected  # Add detected elements unconditionally

    # Compare each sub-rule with expected values
    for key, expected in expected_value.items():
        detected = rule_value.get(key, "Not detected")

        # Specific handling for empty_passwords: List comparison
        if isinstance(expected, list) and isinstance(detected, list):
            if set(detected) != set(expected):
                non_compliant_items[key] = {
                    "detected": detected,
                    "expected": expected
                }
        elif detected != expected:
            if key == 'faillock':
                result = check_faillock_compliance(detected, expected)
                if result:
                    non_compliant_items[key] = result
            elif key == 'expiration_policy':
                result = check_expiration_policy_compliance(detected, expected)
                if result:
                    non_compliant_items[key] = result
            else:
                non_compliant_items[key] = {"detected": detected, "expected": expected}

    return {
        "apply": False if non_compliant_items else True,
        "status": "Non-Compliant" if non_compliant_items else "Compliant",
        "detected_elements": detected_items,
        "expected_elements": expected_value
    }

def check_faillock_compliance (detected , expected) : 
    detected = int(detected)
    expected = int(expected)
    if detected <= expected : 
        return {}
    return {"detected": detected,"expected": expected}
    
def check_expiration_policy_compliance (detected , expected) : 
    detected = int(detected)
    expected = int(expected)
    if detected <= expected : 
        return {}
    return {"detected": detected,"expected": expected}

# Main function to analyze the password policy
def analyse_politique_mdp(serveur, niveau, reference_data=None):
    """Analyze the password policy and generate a YAML compliance report."""
    report = {
        "password": {}
    }

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Checking password policy (R31)")
        password_policy = get_password_policy(serveur)
        report["password"]["R31"] = check_compliance("R31", password_policy, reference_data)

        # Check stored password protection (R68)
        print("-> Checking stored password protection (R68)")
        password_protection = get_stored_passwords_protection(serveur)
        report["password"]["R68"] = check_compliance("R68", password_protection, reference_data)

    elif niveau == "moyen":
        print("-> No rules defined for medium level.")
        compliance_percentage = 100.00
        print(f"\nCompliance rate for level {niveau} (Password policy) : {compliance_percentage:.2f}%")
        return

    # Save the report
    save_yaml_report(report, f"analyse_{niveau}.yml")
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    # Calculate compliance rate
    total_rules = len(report["password"])
    conforming_rules = sum(1 for result in report["password"].values() if result["status"] == "Compliant")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nCompliance rate for level {niveau} (Password policy) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
    
# R31 - Check password policy
def get_password_policy(serveur):
    """Analyze the system's password policy."""
    policy_data = {}

    # 1. Check password policy in PAM (Normalize output)
    pam_policy_raw = execute_remote_command(
        serveur, "sudo grep -E 'pam_pwquality.so|pam_unix.so' /etc/pam.d/common-password",
        "Detected", "No PAM policy detected"
    )
    
    if pam_policy_raw != "No PAM policy detected":
        pam_policy_cleaned = " ".join(pam_policy_raw.split())
        policy_data["pam_policy"] = pam_policy_cleaned
    else:
        policy_data["pam_policy"] = "Not detected"

    # 2. Check password expiration with `chage`
    expiration_policy_raw = execute_remote_command(
        serveur, "sudo chage -l $(whoami) | awk -F': ' '/Maximum number of days between password change/ {print $2}'",
        "Detected", "-1"
    )

    try:
        policy_data["expiration_policy"] = int(expiration_policy_raw.strip())
    except ValueError:
        policy_data["expiration_policy"] = -1

    # 3. Check if faillock is enabled
    faillock_raw = execute_remote_command(
        serveur, "sudo grep '^deny\\s*=' /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' '",
        "Detected", "-1"
    )

    try:
        policy_data["faillock"] = int(faillock_raw.strip())
    except ValueError:
        policy_data["faillock"] = -1

    return policy_data


# R68 - Check stored password protection
def get_stored_passwords_protection(serveur):
    """Analyze the security of stored passwords in /etc/shadow by checking permissions,
    the presence of hashed passwords, and the hashing algorithm configuration."""
    password_protection_status = {}

    # 1. Check permissions of /etc/shadow
    password_protection_status["shadow_permissions"] = execute_remote_command(
        serveur, "ls -l /etc/shadow | awk '{print $1, $3, $4}'",
        "Detected", "Permissions not found"
    )

    # 2. Check the presence of hashed passwords
    hashed_passwords = execute_remote_command(
        serveur, "sudo grep -E '^[^:]+:[!$]' /etc/shadow | wc -l",
        "Yes", "No"
    )
    password_protection_status["hashed_passwords"] = "Yes" if hashed_passwords != "No" else "No"

    # 3. Check the presence of cleartext passwords
    password_protection_status["cleartext_passwords"] = execute_remote_command(
        serveur, "sudo grep -E '^[^:]+:[^!$*]' /etc/shadow",
        "Yes (Risk detected)", "No"
    )

    # 4. Check if accounts have empty passwords
    empty_passwords = execute_remote_command(
        serveur, "sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow",
        "Detected", "None"
    )
    password_protection_status["empty_passwords"] = empty_passwords.split("\n") if empty_passwords != "None" else []

    # 5. Check the hashing algorithms used in /etc/shadow
    detected_hashes = execute_remote_command(
        serveur, "sudo awk -F':' '{print $2}' /etc/shadow | grep -E '^\$[0-9a-zA-Z]+\$' | cut -d'$' -f2 | sort -u",
        "Not detected", "Not detected"
    )
    password_protection_status["hash_algorithms"] = detected_hashes.split("\n") if detected_hashes != "Not detected" else ["Not detected"]
    
    return password_protection_status

# Execute a command on the remote server and return a standardized output
def execute_remote_command(serveur, command, expected_output, default_output):
    """Execute a remote command and normalize the output."""
    try:
        stdin, stdout, stderr = serveur.exec_command(command)
        output = stdout.read().decode().strip()
        return output if output else default_output
    except Exception as e:
        print(f"Error executing command : {command} -> {e}")
        return default_output

# Save the analysis report in YAML format
def save_yaml_report(data, output_file):
    """Save analysis data to a YAML file in the dedicated folder."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True , indent=4, sort_keys=False)

    print(f"Report generated : {output_path}")
