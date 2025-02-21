import yaml
import os
import paramiko

# Execute an SSH command on the remote server and return the result
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Check compliance of rules by comparing detected values with references
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = []
    
    # Flatten expected values to match detected values format
    if isinstance(expected_values, dict):
        for key, value in expected_values.items():
            if isinstance(value, list):
                expected_values_list.extend(value)
            else:
                expected_values_list.append(value)
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    
    return {
        "apply": False if detected_values else True,
        "status": "Compliant" if not detected_values else "Non-compliant",
        "expected_elements": expected_values_list or "None",
        "detected_elements": detected_values or "None"
    }

# Define functions for each rule

def get_standard_users(serveur):
    return set(execute_ssh_command(serveur, "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"))

def get_recent_users(serveur):
    return set(execute_ssh_command(serveur, "last -s -60days -F | awk '{print $1}' | grep -v 'wtmp' | sort | uniq"))

def get_disabled_users(serveur):
    return set(execute_ssh_command(serveur, "awk -F: '($2 ~ /^!|^\\*/) {print $1}' /etc/shadow"))

def get_inactive_users(serveur):
    return list((get_standard_users(serveur) - get_recent_users(serveur)) - get_disabled_users(serveur))

def find_orphan_files(serveur):
    return execute_ssh_command(serveur, "sudo find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null")

def find_files_with_setuid_setgid(serveur):
    return execute_ssh_command(serveur, "find / -type f -perm /6000 -print 2>/dev/null")

def get_service_accounts(serveur):
    return execute_ssh_command(serveur, "awk -F: '($3 < 1000) && ($1 != \"root\") {print $1}' /etc/passwd")

def get_sudo_directives(serveur):
    return execute_ssh_command(serveur, "sudo grep -E '^Defaults' /etc/sudoers")

def get_non_privileged_sudo_users(serveur):
    return execute_ssh_command(serveur, "sudo grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\\(ALL.*\\)' | grep -Ev '(NOPASSWD|%sudo|root)'")

def get_negation_in_sudoers(serveur):
    return execute_ssh_command(serveur, "sudo grep -E '!' /etc/sudoers")

def get_strict_sudo_arguments(serveur):
    return execute_ssh_command(serveur, "sudo grep -E 'ALL=' /etc/sudoers | grep -E '\\*'")

def get_sudoedit_usage(serveur):
    return execute_ssh_command(serveur, "sudo grep -E 'ALL=.*sudoedit' /etc/sudoers")

def get_secure_permissions(serveur):
    return execute_ssh_command(serveur, "sudo find / -type f -perm -0002 -ls 2>/dev/null")

def get_protected_sockets(serveur):
    return execute_ssh_command(serveur, "sudo ss -xp | awk '{print $5}' | cut -d':' -f1 | sort -u")

def get_user_private_tmp(serveur):
    return execute_ssh_command(serveur, "mount | grep ' /tmp '")

# Analyze access management and generate a report
def analyse_gestion_acces(serveur, niveau, reference_data):
    if reference_data is None:
        reference_data = {}
        
    report = {}
    rules = {
        "min": {
            "R30": (get_inactive_users, "Disable unused user accounts"),
            "R53": (find_orphan_files, "Avoid files or directories without a known user or group"),
            "R56": (find_files_with_setuid_setgid, "Limit executables with setuid/setgid"),
        },
        "moyen": {
            "R34": (get_service_accounts, "Disable unused service accounts"),
            "R39": (get_sudo_directives, "Ensure proper sudo configuration"),
            "R40": (get_non_privileged_sudo_users, "Restrict sudo privileges to privileged users"),
            "R42": (get_negation_in_sudoers, "Avoid negations in sudo configurations"),
            "R43": (get_strict_sudo_arguments, "Ensure strict argument specification in sudoers"),
            "R44": (get_sudoedit_usage, "Restrict sudo editing to sudoedit"),
            "R50": (get_secure_permissions, "Ensure secure file permissions"),
            "R52": (get_protected_sockets, "Protect named sockets and pipes"),
            "R55": (get_user_private_tmp, "Separate user temporary directories"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 0
    print(f"\nCompliance rate for niveau {niveau.upper()}: {compliance_percentage:.2f}%")

# Save the analysis report in YAML format
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file: 
        print(output_path)
        file.write("gestion_acces:\n") 

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






# R67 
# print("-> Vérification de la sécurisation de l'authentification distante via PAM (R67)")
# pam_security = check_pam_security(serveur, reference_data)
# report["R67"] = check_compliance("R67", pam_security, reference_data)

# # Vérification de conformité adaptée pour chaque règle
# def check_compliance(rule_id, rule_value, reference_data):
#     """Vérifie la conformité en fonction de la règle donnée et gère le cas particulier de R67."""

#     # Charger les valeurs attendues depuis Reference_Moyen.yaml
#     expected_value = reference_data.get(rule_id, {}).get("expected", {})

#     if rule_id == "R67":
#         # Construire la liste des éléments attendus sous le même format que les éléments détectés
#         expected_list = [f"detected_pam_modules: {expected_value.get('detected_pam_modules', '')}"] + \
#                         [f"{module}: {status}" for module, status in expected_value.get("security_modules", {}).items()]

#         # Vérifier si tous les éléments détectés correspondent exactement aux valeurs attendues
#         is_compliant = set(rule_value) == set(expected_list)

#         compliance_result = {
#             "rule_id": rule_id,
#             "status": "Conforme" if is_compliant else "Non conforme",
#             "appliquer": is_compliant,  # Maintenant, appliquer = True si conforme
#             "éléments_attendus": expected_value,  # Toujours afficher les éléments attendus
#             "éléments_detectés": rule_value if rule_value else []  # Assurer une liste bien formatée
#         }
#     else:
#         # Cas général pour les autres règles
#         if not isinstance(expected_value, list):
#             expected_value = []

#         is_compliant = not rule_value  # Conforme si rule_value est vide

#         compliance_result = {
#             "rule_id": rule_id,
#             "status": "Conforme" if is_compliant else "Non conforme",
#             "appliquer": is_compliant,  # Maintenant, appliquer = True si conforme
#             "éléments_attendus": expected_value if expected_value else "Non spécifié",
#             "éléments_detectés": rule_value if rule_value else []  # Assurer une liste bien formatée
#         }

#     return compliance_result

# # R67 - Sécuriser les authentifications distantes par PAM
# def check_pam_security(serveur, reference_data):
#     """Vérifie si l'authentification à distance via PAM est sécurisée (R67)."""

#     # Charger les valeurs attendues depuis Reference_Moyen.yaml
#     expected_values = reference_data.get("R67", {}).get("expected", {})

#     # Vérifier l'utilisation du module d'authentification distant (pam_ldap attendu)
#     command_pam_auth = "grep -Ei 'pam_ldap' /etc/pam.d/* 2>/dev/null"
#     stdin, stdout, stderr = serveur.exec_command(command_pam_auth)
#     detected_pam_entries = stdout.read().decode().strip().split("\n")

#     # Si pam_ldap est détecté, l'afficher, sinon "Non trouvé"
#     detected_pam_module = "pam_ldap" if detected_pam_entries and any("pam_ldap" in line for line in detected_pam_entries) else "Non trouvé"

#     # Vérifier la présence des modules de sécurité requis
#     security_modules = expected_values.get("security_modules", {})
#     detected_security_modules = {}

#     for module in security_modules.keys():
#         command = f"grep -E '{module}' /etc/pam.d/* 2>/dev/null"
#         stdin, stdout, stderr = serveur.exec_command(command)
#         detected_status = "Enabled" if stdout.read().decode().strip() else "Non trouvé"
        
#         # Stocker la valeur détectée
#         detected_security_modules[module] = detected_status

#     # Construire les éléments détectés
#     detected_elements = {
#         "detected_pam_modules": detected_pam_module,
#         "security_modules": detected_security_modules
#     }

#     # Construire la liste des éléments détectés (inclut tous les éléments attendus)
#     detected_list = []

#     # Ajouter les modules PAM LDAP
#     detected_list.append(f"detected_pam_modules: {detected_elements['detected_pam_modules']}")

#     # Ajouter les modules de sécurité PAM
#     for module, detected_status in detected_elements["security_modules"].items():
#         detected_list.append(f"{module}: {detected_status}")

#     return detected_list

