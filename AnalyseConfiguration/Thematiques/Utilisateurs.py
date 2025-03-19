import yaml
import os
import paramiko
import re
from GenerationRapport.GenerationRapport import generate_html_report

# -------------------------
# Helper Functions
# -------------------------

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

# Execute an SSH command on the remote server and return the output as a list of lines.
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip().split("\n")
    return list(filter(None, output))

# -------------------------
# Compliance Check Functions
# -------------------------

# Check compliance for a given rule by comparing detected values with expected reference values.
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
        expected_vals = reference_data.get(rule_id, {}).get("expected", {})
        compare_values(detected_values, expected_vals)
        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": detected_values or "None",
            "expected_elements": expected_vals or "None"
        }
    elif rule_id == "R70":
        local_users = set(detected_values.get("local_users", []))
        system_users = set(detected_values.get("system_users", []))
        admin_users = set(detected_values.get("admin_users", []))
        ldap_users = detected_values.get("ldap_users", [])
        overlap = admin_users.intersection(local_users.union(system_users))
        is_compliant = not overlap and not ldap_users
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
        discrepancies = {}
        is_compliant = True
        expected_vals = reference_data.get("R69", {}).get("expected", {})
        remote_db_detected = detected_values.get("uses_remote_db")
        if not remote_db_detected or remote_db_detected == "None":
            is_compliant = False
        secure_connection_detected = detected_values.get("secure_connection", "").lower()
        if "tls" not in secure_connection_detected:
            is_compliant = False
        binddn_user_detected = detected_values.get("binddn_user", "")
        if "cn=" not in binddn_user_detected or "dc=" not in binddn_user_detected:
            is_compliant = False
        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": detected_values,
            "expected_elements": expected_vals
        }
    elif rule_id == "R36":
        detected_umask = detected_values.get("umask", "")
        allowed_vals = ["027", "0027", "077", "0077"]
        compliance = detected_umask in allowed_vals 
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "detected_elements": detected_umask if detected_umask else "None"
        }
    elif rule_id == "R37":
        detected_interfaces = set(detected_values.get("listen_interfaces", []))
        expected_interfaces = set(reference_data.get(rule_id, {}).get("expected", {}).get("hardened_mail_service", {}).get("listen_interfaces", []))
        detected_local_delivery = set(detected_values.get("allow_local_delivery", []))
        expected_local_delivery = set(reference_data.get(rule_id, {}).get("expected", {}).get("hardened_mail_service", {}).get("allow_local_delivery", []))
        compliance = (detected_interfaces == expected_interfaces) and (detected_local_delivery == expected_local_delivery)
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "detected_elements": {
                "listen_interfaces": list(detected_interfaces),
                "allow_local_delivery": list(detected_local_delivery)
            },
            "expected_elements": {
                "listen_interfaces": list(expected_interfaces),
                "allow_local_delivery": list(expected_local_delivery)
            }
        }
    elif rule_id == "R45":
        compliance = detected_values.get("apply", False)
        detected_list = detected_values.get("detected_elements", [])
        return {
            "apply": compliance,
            "status": "Compliant" if compliance else "Non-Compliant",
            "expected_elements": "All AppArmor profiles should be in enforce mode (complain mode count: 0)",
            "detected_elements": detected_list
        }
    elif rule_id == "R50":
        expected_vals = reference_data.get("R50", {}).get("expected", [])
        expected_dict = {}
        for entry in expected_vals:
            parts = entry.split()
            if len(parts) == 2:
                expected_dict[parts[0]] = parts[1]
        non_compliant = any(
            item.split()[-2] != expected_dict.get(item.split()[-3], "")
            for item in detected_values
        ) if detected_values else False
        return {
            "apply": not non_compliant,
            "status": "Compliant" if (not non_compliant or not detected_values) else "Non-Compliant",
            "detected_elements": detected_values or "None"
        }
    elif rule_id == "R41":
        expected_vals = reference_data.get("R41", {}).get("expected", {}).get("noexec_commands", [])
        if not detected_values:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": expected_vals,
                "detected_elements": "None"
            }
        detected_set = set(detected_values)
        expected_set = set(expected_vals)
        if detected_set == expected_set:
            return {
                "apply": True,
                "status": "Compliant",
                "expected_elements": expected_vals,
                "detected_elements": detected_values
            }
        else:
            unexpected = list(detected_set - expected_set)
            missing = list(expected_set - detected_set)
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": expected_vals,
                "detected_elements": detected_values,
                "unexpected_elements": unexpected or None,
                "missing_elements": missing or None
            }
    elif rule_id == "R57":
        expected_execs = set(reference_data.get("R57", {}).get("expected", []))
        detected_execs = set(detected_values) if detected_values else set()
        unauthorized = detected_execs - expected_execs
        if unauthorized:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": sorted(list(expected_execs)),
                "detected_elements": sorted(list(detected_execs)),
                "unauthorized_elements": sorted(list(unauthorized))
            }
        else:
            return {
                "apply": True,
                "status": "Compliant",
                "detected_elements": sorted(list(detected_execs)) or "None"
            }
    elif rule_id == "R64":
        expected_services = set(reference_data.get("R64", {}).get("expected", []))
        detected_services = set(detected_values or [])
        unauthorized = detected_services - expected_services
        if unauthorized:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": list(expected_services),
                "detected_elements": list(detected_services),
                "unauthorized_elements": list(unauthorized)
            }
        else:
            return {
                "apply": True,
                "status": "Compliant",
                "detected_elements": list(detected_services) or "None"
            }
    else:
        is_compliant = not detected_values
        status = "Compliant" if is_compliant else "Non-Compliant"
        return {
            "apply": is_compliant,
            "status": status,
            "detected_elements": detected_values or "None"
        }

# -------------------------
# Remote command functions with os_info checks
# -------------------------

def check_tmout(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        tmout_output = execute_ssh_command(serveur, "grep -E '^TMOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null | awk -F= '{print $2}' | sort -u")
        tmout_value = tmout_output[0] if tmout_output else "None"
        return {
            "TMOUT": tmout_value,
            "logind_conf": check_logind_conf(serveur, os_info)
        }
    else:
        print(f"[check_tmout] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); TMOUT check skipped.")
        return {"TMOUT": "Not checked", "logind_conf": {}}

def check_logind_conf(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        logind_settings = {"IdleAction": "Not defined", "IdleActionSec": "Not defined", "RuntimeMaxSec": "Not defined"}
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
    else:
        print(f"[check_logind_conf] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); logind config check skipped.")
        return {}

def get_user_info(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return {
            "local_users": execute_ssh_command(serveur, "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"),
            "system_users": execute_ssh_command(serveur, "awk -F: '$3 < 1000 {print $1}' /etc/passwd"),
            "admin_users": execute_ssh_command(serveur, "getent group sudo | awk -F: '{print $4}'"),
            "ldap_users": execute_ssh_command(serveur, "getent passwd | awk -F: '$1 ~ /^ldap/ {print $1}'")
        }
    else:
        print(f"[get_user_info] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); user info not retrieved.")
        return {"local_users": [], "system_users": [], "admin_users": [], "ldap_users": []}

def check_remote_user_database_security(serveur, reference_data, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
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
    else:
        print(f"[check_remote_user_database_security] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); remote user database security check skipped.")
        return {
            "uses_remote_db": "Not checked",
            "secure_connection": "Not checked",
            "binddn_user": "Not checked",
            "limited_rights": "Not checked"
        }

# Duplicate definition of execute_ssh_command omitted.

def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    # Open file in write mode to avoid duplicate top-level keys.
    with open(output_path, "w", encoding="utf-8") as file:
        file.write("users:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, (None, ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False)
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
        file.write("\n")
    print(f"Report generated: {output_path}")

# -------------------------
# Main function for user analysis
# -------------------------
def analyse_utilisateurs(serveur, niveau, reference_data=None, os_info=None):
    # Initialize report as an empty dictionary (avoid nested "users:" keys)
    report = {}
    reference_data = reference_data or load_reference_yaml(niveau)
    rules = {
        "min": {},
        "moyen": {
            "R32": (check_tmout, "Session timeout verification"),
            "R70": (get_user_info, "Separation of system and admin accounts"),
            "R69": (check_remote_user_database_security, "Securing remote user databases")
        },
        "renforce": {}
    }
    if niveau in rules and rules[niveau]:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> {comment} ({rule_id})")
            if rule_id == 'R69':
                report[rule_id] = check_compliance(rule_id, function(serveur, reference_data, os_info), reference_data)
            else:
                report[rule_id] = check_compliance(rule_id, function(serveur, os_info), reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in Users.")
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"
    compliance_percentage = (sum(1 for r in report.values() if r and r.get("status") == "Compliant") / len(report) * 100) if report else 100
    print(f"\nCompliance rate for level {niveau.upper()} (Users): {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

# -------------------------
# Functions for user analysis that use SSH commands, with os_info checks.
# -------------------------
def check_tmout(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        tmout_output = execute_ssh_command(serveur, "grep -E '^TMOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null | awk -F= '{print $2}' | sort -u")
        tmout_value = tmout_output[0] if tmout_output else "None"
        return {
            "TMOUT": tmout_value,
            "logind_conf": check_logind_conf(serveur, os_info)
        }
    else:
        print(f"[check_tmout] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); TMOUT check skipped.")
        return {"TMOUT": "Not checked", "logind_conf": {}}

def check_logind_conf(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        logind_settings = {"IdleAction": "Not defined", "IdleActionSec": "Not defined", "RuntimeMaxSec": "Not defined"}
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
    else:
        print(f"[check_logind_conf] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); logind config check skipped.")
        return {}
