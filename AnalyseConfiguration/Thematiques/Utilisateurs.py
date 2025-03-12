import yaml
import os
import paramiko
import re
from GenerationRapport.GenerationRapport import generate_html_report

# Load reference data from Reference_min.yaml or Reference_Moyen.yaml based on level
def load_reference_yaml(niveau):
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return {}

# Convert a time value to seconds
def convert_to_seconds(value):
    if isinstance(value, str):
        value = value.lower().replace(" ", "")  # Remove spaces
        match = re.match(r"(\d+)(h|min|s)", value)
        if match:
            num, unit = match.groups()
            num = int(num)
            if unit == "h":
                return num * 3600
            elif unit == "min":
                return num * 60
            elif unit == "s":
                return num
        try:
            return int(value)
        except ValueError:
            return value  # Return raw value if conversion fails
    return value

# Check compliance for a given rule by comparing detected values with expected reference values
def check_compliance(rule_id, detected_values, reference_data):
    if rule_id == "R32":
        discrepancies = {}
        is_compliant = True

        def compare_values(detected, expected, path=""):
            nonlocal is_compliant
            if isinstance(detected, dict) and isinstance(expected, dict):
                for key in expected:
                    compare_values(detected.get(key, "Not defined"), expected[key], path + key + ".")
            else:
                detected_converted = convert_to_seconds(detected)
                expected_converted = convert_to_seconds(expected)
                if isinstance(detected_converted, int) and isinstance(expected_converted, int):
                    if detected_converted > expected_converted:
                        discrepancies[path[:-1]] = {"detected": detected, "expected": expected}
                        is_compliant = False

        expected_values = reference_data.get(rule_id, {}).get("expected", {})
        compare_values(detected_values, expected_values)
        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": detected_values or "None",
            "expected_elements": expected_values or "None"
        }

    elif rule_id == "R70":
        # Check separation of system and admin accounts
        local_users = set(detected_values.get("local_users", []))
        system_users = set(detected_values.get("system_users", []))
        admin_users = set(detected_values.get("admin_users", []))
        ldap_users = detected_values.get("ldap_users", [])

        overlap = admin_users.intersection(local_users.union(system_users))
        is_compliant = True
        if overlap:
            is_compliant = False

        if ldap_users:
            is_compliant = False

        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": detected_values,
            "expected_elements": {
                "admin_users": "Must be distinct from local_users and system_users",
                "ldap_users": "Must be empty"
            },
        }

    elif rule_id == "R69":
        # Check security of remote user database access according to the standard
        discrepancies = {}
        is_compliant = True
        expected_values = reference_data.get("R69", {}).get("expected", {})

        # For uses_remote_db: if something is found, it's good
        remote_db_detected = detected_values.get("uses_remote_db")
        if not remote_db_detected or remote_db_detected == "None":
            is_compliant = False

        # For secure_connection: if the string does not contain "tls", then it's false
        secure_connection_detected = detected_values.get("secure_connection", "").lower()
        if "tls" not in secure_connection_detected:
            is_compliant = False

        # For binddn_user: if it does not contain fields like "cn=" and "dc=", then it's false
        binddn_user_detected = detected_values.get("binddn_user", "")
        if "cn=" not in binddn_user_detected or "dc=" not in binddn_user_detected:
            is_compliant = False

        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": detected_values,
        }

    else:
        return {
            "status": "Compliant",
            "apply": True,
            "detected_elements": detected_values or "None"
        }

# Analyze user configurations on the server and generate a YAML report
def analyse_utilisateurs(serveur, niveau, reference_data=None):
    report = {}
    reference_data = reference_data or load_reference_yaml(niveau)

    rules = {
        "moyen": {
            "R32": (check_tmout, "Session timeout verification"),
            "R70": (get_user_info, "Separation of system and admin accounts"),
            "R69": (check_remote_user_database_security, "Securing remote user databases")
        }
    }
    
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> {comment} ({rule_id})")
            report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in Users.")

    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"

    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (Users): {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
    
# Check session timeout configuration and logind settings
def check_tmout(serveur):
    tmout_output = execute_ssh_command(serveur, "grep -E '^TMOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null | awk -F= '{print $2}' | sort -u")
    tmout_value = tmout_output[0] if tmout_output else "None"
    return {
        "TMOUT": tmout_value,
        "logind_conf": check_logind_conf(serveur)
    }

# Check systemd-logind settings by excluding commented lines
def check_logind_conf(serveur):
    logind_settings = {
        "IdleAction": "Not defined",
        "IdleActionSec": "Not defined",
        "RuntimeMaxSec": "Not defined"
    }
    command_logind = "sudo grep -E '^(IdleAction|IdleActionSec|RuntimeMaxSec)=' /etc/systemd/logind.conf | grep -v '^#'"
    stdin, stdout, stderr = serveur.exec_command(command_logind)
    logind_output = stdout.read().decode().strip().split("\n")
    for line in logind_output:
        if "=" in line:
            key, value = line.strip().split("=", 1)
            if key in logind_settings:
                logind_settings[key] = value.strip()
    for key in ["IdleActionSec", "RuntimeMaxSec"]:
        if logind_settings[key] != "Not defined" and not logind_settings[key].endswith("s"):
            try:
                int_value = int(logind_settings[key])
                logind_settings[key] = f"{int_value}s"
            except ValueError:
                pass
    return logind_settings

# Retrieve user information from the server
def get_user_info(serveur):
    return {
        "local_users": execute_ssh_command(serveur, "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"),
        "system_users": execute_ssh_command(serveur, "awk -F: '$3 < 1000 {print $1}' /etc/passwd"),
        "admin_users": execute_ssh_command(serveur, "getent group sudo | awk -F: '{print $4}'"),
        "ldap_users": execute_ssh_command(serveur, "getent passwd | awk -F: '$1 ~ /^ldap/ {print $1}'")
    }

# Check security of remote user databases according to reference data
def check_remote_user_database_security(serveur, reference_data=None):
    expected_values = {}
    if reference_data:
        expected_values = reference_data.get("R69", {}).get("expected", {})
    command_nsswitch = ("grep -E '^(passwd|group|shadow):' /etc/nsswitch.conf | "
                        "awk '{for (i=2; i<=NF; i++) print $0}' | sort -u")
    nss_sources = execute_ssh_command(serveur, command_nsswitch)
    nss_sources = [src.strip() for src in nss_sources if src.strip()]
    expected_remote_db = expected_values.get("uses_remote_db", "None")
    uses_remote_db = expected_remote_db if expected_remote_db in nss_sources else "None"
    if uses_remote_db == "None":
        print("No remote user database detected.")
        return {
            "uses_remote_db": "None",
            "secure_connection": "None",
            "binddn_user": "None",
            "limited_rights": "None"
        }
    command_tls = ("grep -i 'tls' /etc/ldap/ldap.conf /etc/sssd/sssd.conf 2>/dev/null | "
                   "grep -v '^#' | awk -F':' '{print $2}' | sed 's/^[ \\t]*//g' | sort -u")
    tls_config = execute_ssh_command(serveur, command_tls)
    expected_tls = expected_values.get("secure_connection", "").lower()
    secure_connection = "None"
    if expected_tls in ["start_tls", "ssl"] and any(expected_tls in item.lower() for item in tls_config):
        secure_connection = expected_tls
    elif "TLS_CACERT" in " ".join(tls_config) or "TLS_REQCERT" in " ".join(tls_config):
        secure_connection = "tls"
    command_binddn = ("grep -i 'bind' /etc/sssd/sssd.conf /etc/ldap/ldap.conf 2>/dev/null | "
                      "awk -F'=' '{print substr($0, index($0,$2))}' | sed 's/^[ \\t]*//g'")
    binddn_user_list = execute_ssh_command(serveur, command_binddn)
    binddn_user = binddn_user_list[0] if binddn_user_list else ""
    if not binddn_user:
        binddn_user = "Not defined"
    expected_binddn = expected_values.get("binddn_user", "")
    binddn_user_status = binddn_user if binddn_user == expected_binddn else "Not properly defined"
    expected_rights = expected_values.get("limited_rights", "")
    limited_rights = expected_rights if "service_account" in binddn_user.lower() else "No"
    return {
        "uses_remote_db": uses_remote_db,
        "secure_connection": secure_connection,
        "binddn_user": binddn_user_status,
        "limited_rights": limited_rights
    }

# Execute an SSH command on the server and return the output as a list of lines
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Save the generated report in YAML format to the specified directory
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "a", encoding="utf-8") as file:
        file.write("users:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, (None, ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False)
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
        file.write("\n")
    print(f"Report generated: {output_path}")
