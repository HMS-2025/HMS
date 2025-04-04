import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Load the reference file corresponding to the selected level (min, moyen, or renforce).
def load_reference_yaml(niveau):
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return {}

# Check rule compliance by comparing detected values with reference data.
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})

    # Specific exception for R62: detected prohibited services
    if rule_id == "R62":
        detected_prohibited_elements = detected_values.get("detected_prohibited_elements", [])
        is_compliant = len(detected_prohibited_elements) == 0
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": detected_values.get("detected_elements", []),
            "detected_prohibited_elements": detected_prohibited_elements,
            "expected_elements": expected_values
        }
    # Specific exception for rules R74 and R75 if no mail server detected
    if rule_id == "R74":
        if (not detected_values or
            not detected_values.get("listen_interfaces") or
            not detected_values.get("allow_local_delivery")):
            # No mail server present: compliant by default
            return {
                "apply": True,
                "status": "Compliant",
                "detected_elements": {
                    "listen_interfaces": [],
                    "allow_local_delivery": []
                },
                "expected_elements": expected_values.get("hardened_mail_service", {})
            }
        detected_interfaces = set(detected_values.get("listen_interfaces", []))
        expected_interfaces = set(expected_values.get("hardened_mail_service", {}).get("listen_interfaces", []))
        detected_local_delivery = set(detected_values.get("allow_local_delivery", []))
        is_compliant = (detected_interfaces == expected_interfaces)
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": {
                "listen_interfaces": list(detected_interfaces),
                "allow_local_delivery": list(detected_local_delivery)
            },
            "expected_elements": {
                "listen_interfaces": list(expected_interfaces),
            }
        }

    elif rule_id == "R75":
        postfix_installed = detected_values.get("postfix_installed", False)

        # If postfix is ​​not installed: compliant by default
        if not postfix_installed:
            return {
                "apply": True,
                "status": "Compliant",
                "detected_elements": {
                    "postfix_installed": False
                },
                "expected_elements": expected_values.get("mail_aliases", [])
            }

        detected_aliases = detected_values.get("detected_elements", [])
        expected_aliases = expected_values.get("expected_elements", [])
        is_compliant = any(alias in detected_aliases for alias in expected_aliases)

        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": {
                "aliases": detected_aliases,
                "postfix_installed": True
            },
            "expected_elements": expected_aliases
        }

    # Specific case for R10: Check that /proc/sys/kernel/modules_disabled == 1
    elif rule_id == "R10":
        is_compliant = (detected_values.get("detected_elements", "") == "1")
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": detected_values.get("detected_elements", ""),
            "expected_elements": "1"
        }
    # Standard handling for other rules
    else:
        return {
            "apply": detected_values == expected_values,
            "status": "Compliant" if detected_values == expected_values else "Non-Compliant",
            "expected_elements": expected_values or "None",
            "detected_elements": detected_values or "None"
        }

# Execute an SSH command on the remote server and return the output as a list of lines.
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip().split("\n")
    return list(filter(None, output))

# Check active services and determine compliance based on the prohibited services list.
def disable_unnecessary_services(serveur, reference_data, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        disallowed_services = reference_data.get("R62", {}).get("expected", {}).get("disallowed_services", [])
        if not disallowed_services:
            print("No prohibited services defined. Check the reference_min.yaml file.")
            return {}
        active_services = get_active_services(serveur, os_info)
        forbidden_running_services = [service for service in active_services if service in disallowed_services]
        is_compliant = len(forbidden_running_services) == 0
        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": active_services,
            "detected_prohibited_elements": forbidden_running_services
        }
    else:
        print("[disable_unnecessary_services] Non-Ubuntu OS; action skipped.")
        return {}

# Retrieve the list of active services on the remote server.
def get_active_services(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        try:
            command_services = "systemctl list-units --type=service --state=running | awk '{print $1}'"
            services = execute_ssh_command(serveur, command_services)
            cleaned_services = []
            for service in services:
                if service.lower() == "load":
                    break  # Stop processing after "ACTIVE"
                if service and not service.startswith("●") and service.lower() not in ["unit"]:
                    cleaned_services.append(service.strip())
            return cleaned_services
        except Exception as e:
            print(f"Error retrieving active services: {e}")
            return []
    else:
        print("[get_active_services] Non-Ubuntu OS; active services not retrieved.")
        return []

# Check if each service has a unique system account.
def check_unique_service_accounts(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "ps -eo user,comm | awk '{print $1}' | sort | uniq -c"
        output = execute_ssh_command(serveur, command)
        non_unique_accounts = [line.strip() for line in output if int(line.split()[0]) > 1]
        return non_unique_accounts if non_unique_accounts else []
    else:
        print("[check_unique_service_accounts] Non-Ubuntu OS; check skipped.")
        return []

# Check services for enabled Linux capabilities.
def check_disabled_service_features(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "find / -type f -perm /111 -exec getcap {} \; 2>/dev/null"
        return execute_ssh_command(serveur, command)
    else:
        print("[check_disabled_service_features] Non-Ubuntu OS; check skipped.")
        return []

# Check if the mail service only accepts local connections and allows only local delivery.
def check_hardened_mail_service(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command_listen = "ss -tuln | grep ':25' | awk '{print $5}'"
        detected_interfaces = [line.strip() for line in execute_ssh_command(serveur, command_listen) if line.strip()]
        command_destination = "postconf -h mydestination"

        mydestination_raw = " ".join(execute_ssh_command(serveur, command_destination))
        detected_local_delivery = [item.strip() for item in mydestination_raw.split(",") if item.strip()]
        print(f"les interface {detected_interfaces} et {detected_local_delivery}")

        return {
            "listen_interfaces": detected_interfaces,
            "allow_local_delivery": detected_local_delivery
        }
    else:
        print("[check_hardened_mail_service] Non-Ubuntu OS; check skipped.")
        return {}

# Check for the presence of mail aliases for service accounts.
def check_mail_aliases(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        # Check if postfix is installed
        command_check_postfix = "dpkg -l | grep postfix"
        postfix_installed = execute_ssh_command(serveur, command_check_postfix)

        postfix_present = bool(postfix_installed)
        if not postfix_present:  # Postfix not detected: compliant by default
            print("[check_mail_aliases] Postfix non détecté; règle conforme par défaut.")
            return {
                "detected_elements": [],
                "expected_elements": [],
                "postfix_installed": False
            }

        # Postfix is installed: check aliases
        command_aliases = "grep -E '^[a-zA-Z0-9._-]+:' /etc/aliases | awk -F':' '{print $1}' 2>/dev/null"
        aliases_output = execute_ssh_command(serveur, command_aliases)

        reference_data = load_reference_yaml("moyen")
        expected_aliases = reference_data.get("R75", {}).get("expected", {}).get("mail_aliases", [])
        detected_aliases = [alias.strip() for alias in aliases_output if alias.strip()]

        return {
            "detected_elements": detected_aliases,
            "expected_elements": expected_aliases,
            "postfix_installed": True
        }
    else:
        print("[check_mail_aliases] Non-Ubuntu OS; check skipped.")
        return {
            "postfix_installed": False
        }

# Verify that /proc/sys/kernel/modules_disabled contains the value 1.
def check_kernel_modules_disabled(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        try:
            commande = "cat /proc/sys/kernel/modules_disabled"
            stdin, stdout, stderr = serveur.exec_command(commande)
            value = stdout.read().decode().strip()
        except Exception as e:
            print("Error reading /proc/sys/kernel/modules_disabled:", e)
            return {
                "status": "Non-Compliant",
                "apply": False,
                "detected_elements": f"Error: {e}",
                "expected_elements": "1"
            }
        is_compliant = (value == "1")
        return {
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "apply": is_compliant,
            "detected_elements": value if value else "No value detected",
            "expected_elements": "1"
        }
    else:
        print("[check_kernel_modules_disabled] Non-Ubuntu OS; check skipped.")
        return {}

# Retrieve user information from the server.
def get_user_info(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return {
            "local_users": execute_ssh_command(serveur, "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"),
            "system_users": execute_ssh_command(serveur, "awk -F: '$3 < 1000 {print $1}' /etc/passwd"),
            "admin_users": execute_ssh_command(serveur, "getent group sudo | awk -F: '{print $4}'"),
            "ldap_users": execute_ssh_command(serveur, "getent passwd | awk -F: '$1 ~ /^ldap/ {print $1}'")
        }
    else:
        print("[get_user_info] Non-Ubuntu OS; user info not retrieved.")
        return {"local_users": [], "system_users": [], "admin_users": [], "ldap_users": []}

# Check security of remote user database access.
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
        print("[check_remote_user_database_security] Non-Ubuntu OS; remote user database security check skipped.")
        return {
            "uses_remote_db": "Not checked",
            "secure_connection": "Not checked",
            "binddn_user": "Not checked",
            "limited_rights": "Not checked"
        }

# Save the analysis results in a YAML file without aliases.
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    yaml.Dumper.ignore_aliases = lambda *args: True

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("services:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
        file.write("\n")
    print(f"Report generated: {output_path}")
   
# Retrieve the list of all services on the system in a clean format.
def get_all_services(serveur):
    command = "systemctl list-units --type=service --all | awk '{print $1}'"
    services = execute_ssh_command(serveur, command)
    cleaned_services = []
    for service in services:
        if service.lower() == "load":
            break  # Stop processing after "LOAD"
        if service and not service.startswith("●") and service.lower() not in ["unit"]:
            cleaned_services.append(service.strip())
    return cleaned_services

# Check if services are confined and return those that are not.
def check_cloisonnement(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        services = get_all_services(serveur)
        non_cloisonnes = []
        
        for service in services:
            check_commands = {
                "Namespaces": f"systemctl show {service} | grep Namespaces",
                "NoNewPrivileges": f"systemctl show {service} | grep NoNewPrivileges",
                "SystemCallFilter": f"systemctl show {service} | grep SystemCallFilter",
                "Delegate": f"systemctl show {service} | grep Delegate"
            }
            
            cloisonne = False
            for key, command in check_commands.items():
                output = execute_ssh_command(serveur, command)
                if output and any("yes" in line.lower() or "true" in line.lower() for line in output):
                    cloisonne = True
                    break  # If at least one protection is active, the service is confined
            
            if not cloisonne:
                non_cloisonnes.append(service)
        
        return non_cloisonnes
    else:
        print("[check_cloisonnement] Non-Ubuntu OS; check skipped.")
        return []

# Main function to perform service analysis.
def analyse_services(serveur, niveau, reference_data=None, os_info=None):
    report = {}  # Initialize report as an empty dict
    reference_data = reference_data or load_reference_yaml(niveau)
    rules = {
        "min": {
            "R62": (disable_unnecessary_services, "Disable prohibited services"),
        },
        "moyen": {
            "R35": (check_unique_service_accounts, "Verify the uniqueness of service accounts"),
            "R63": (check_disabled_service_features, "Disable non-essential service features"),
            "R74": (check_hardened_mail_service, "Harden local mail service"),
            "R75": (check_mail_aliases, "Verify mail aliases for service accounts"),
        },
        "renforce": {
            "R10": (check_kernel_modules_disabled, "Disable kernel modules loading"),
            "R65": (check_cloisonnement, "Check service confinement")
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            # For R62, the function expects (serveur, reference_data, os_info)
            if rule_id == "R62":
                report[rule_id] = check_compliance(rule_id, function(serveur, reference_data, os_info), reference_data)
            else:
                report[rule_id] = check_compliance(rule_id, function(serveur, os_info), reference_data)
    else:
        print(f"-> No specific rules for level {niveau} in Services.")
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"
    compliance_percentage = (sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100) if report else 0
    print(f"\nCompliance rate for level {niveau.upper()} : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
