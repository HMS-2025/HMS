import yaml
import os
import paramiko
import re
from GenerationRapport.GenerationRapport import generate_html_report

# Execute an SSH command on the remote server and return the result as a list of lines
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Check compliance of rules by comparing detected values with reference data
def check_compliance(rule_id, detected_values, reference_data):
    if rule_id == 'R44':
        return {
            "apply": bool(detected_values),
            "status": "Compliant" if detected_values else "Non-Compliant",
            "detected_elements": detected_values or "None"
        }
    elif rule_id == 'R52':
        # Protect named sockets and pipes
        # Expected values are a list of entries like "/run/dbus 755"
        expected_list = reference_data.get(rule_id, {}).get("expected", [])
        expected_dict = {}
        for entry in expected_list:
            parts = entry.split()
            if len(parts) == 2:
                expected_dict[parts[0]] = parts[1]

        # Function to convert symbolic permission (e.g., drwxr-xr-x) to numeric (e.g., 755)
        def symbolic_to_numeric(sym):
            mapping = {'r': 4, 'w': 2, 'x': 1, '-': 0}
            if len(sym) == 10:
                sym = sym[1:]
            if len(sym) != 9:
                return None
            nums = []
            for i in range(0, 9, 3):
                total = mapping.get(sym[i], 0) + mapping.get(sym[i+1], 0) + mapping.get(sym[i+2], 0)
                nums.append(str(total))
            return "".join(nums)

        # Build a dictionary from detected elements: key = file path, value = numeric permission
        detected_dict = {}
        detected_numeric_list = []
        for line in detected_values:
            parts = line.split()
            if len(parts) >= 4:
                owner = parts[0]
                group = parts[1]
                path = parts[2]
                sym_perm = parts[3]
                num_perm = symbolic_to_numeric(sym_perm)
                detected_dict[path] = num_perm
                detected_numeric_list.append(f"{owner} {group} {path} {num_perm}")

        is_compliant = True
        discrepancies = {}
        for path, exp_perm in expected_dict.items():
            det_perm = detected_dict.get(path)
            if not det_perm:
                discrepancies[path] = {"detected": "Not found", "expected": exp_perm}
                is_compliant = False
            elif det_perm != exp_perm:
                discrepancies[path] = {"detected": det_perm, "expected": exp_perm}
                is_compliant = False

        # Consolidate discrepancies into a single list of differences
        differences_list = []
        for path, diff in discrepancies.items():
            differences_list.append(f"{path} '{diff['detected']}' (expected '{diff['expected']}')")
        status = "Compliant" if is_compliant else "Non-Compliant"
        return {
            "apply": is_compliant,
            "status": status,
            "expected_elements": expected_list if expected_list else "None",
            "detected_elements": detected_numeric_list if detected_numeric_list else "None",
            "differences": differences_list if differences_list else None
        }
    elif rule_id == 'R55':
        # Separate user temporary directories
        # Compliant if PAM configuration contains references to pam_namespace or pam_mktemp.
        # These modules create per-user temporary directories.
        is_compliant = bool(detected_values)
        status = "Compliant" if is_compliant else "Non-Compliant"
        return {
            "apply": is_compliant,
            "status": status,
            "detected_elements": detected_values if detected_values else "None"
        }
    elif rule_id == 'R67':
        # Secure remote authentication via PAM
        is_compliant = True
        discrepancies = {}
        for entry in detected_values:
            if ":" in entry:
                key, val = entry.split(":", 1)
                key = key.strip()
                val = val.strip()
                if key != "pam_wheel" and val == "Non trouvé":
                    discrepancies[key] = {"detected": val, "expected": "Found"}
                    is_compliant = False
                if key == "pam_wheel" and val == "Enabled":
                    discrepancies[key] = {"detected": val, "expected": "Disabled"}
                    is_compliant = False
        status = "Compliant" if is_compliant else "Non-Compliant"
        return {
            "apply": is_compliant,
            "status": status,
            "detected_elements": detected_values if detected_values else "None",
            "discrepancies": discrepancies if discrepancies else None
        }
    elif rule_id == 'R50':
        expected_values = reference_data.get(rule_id, {}).get("expected", [])
        expected_values_dict = {}
        for entry in expected_values:
            parts = entry.split()
            if len(parts) == 2:
                expected_values_dict[parts[0]] = parts[1]
        non_compliant = any(
            item.split()[-2] != expected_values_dict.get(item.split()[-3], "")
            for item in detected_values
        ) if detected_values else False
        return {
            "apply": not non_compliant,
            "status": "Compliant" if (not non_compliant or not detected_values) else "Non-Compliant",
            "detected_elements": detected_values or "None"
        }
    else:
        is_compliant = not detected_values
        status = "Compliant" if is_compliant else "Non-Compliant"
        return {
            "apply": is_compliant,
            "status": status,
            "detected_elements": detected_values or "None"
        }

    # For minimum level rules, if the result is Non-Compliant, ensure that "apply" is False.
    if rule_id in MIN_RULES and result["status"] == "Non-Compliant":
        result["apply"] = False

    return result

# Retrieve standard users from /etc/passwd (users with UID >= 1000, excluding 'nobody')
def get_standard_users(serveur):
    return set(execute_ssh_command(serveur, "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"))

# Retrieve recent users from the 'last' command within the last 60 days
def get_recent_users(serveur):
    return set(execute_ssh_command(serveur, "last -s -60days -F | awk '{print $1}' | grep -v 'wtmp' | sort | uniq"))

# Retrieve disabled users from /etc/shadow (accounts with a locked password)
def get_disabled_users(serveur):
    return set(execute_ssh_command(serveur, "awk -F: '($2 ~ /^!|^\\*/) {print $1}' /etc/shadow"))

# Get inactive users: standard users who haven't logged in recently and are not disabled
def get_inactive_users(serveur):
    return list((get_standard_users(serveur) - get_recent_users(serveur)) - get_disabled_users(serveur))

# Find orphan files (files with no valid owner or group)
def find_orphan_files(serveur):
    return execute_ssh_command(serveur, "sudo find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null")

# Find files with setuid or setgid permissions
def find_files_with_setuid_setgid(serveur):
    ro_mounts = execute_ssh_command(serveur, "findmnt -r -n -o TARGET")
    ro_mounts_list = ro_mounts
    exclusions = ' '.join([f"-path '{mount}/*' -prune -o" for mount in ro_mounts_list])
    find_command = f"find / {exclusions} -type f -perm /6000 -print 2>/dev/null"
    return execute_ssh_command(serveur, find_command)

# Get service accounts (system accounts with UID < 1000 except root)
def get_service_accounts(serveur):
    command = "sudo awk -F: 'FNR==NR { shadow[$1]=$2; next } ($3 < 1000 && $3 != 0) && ($7 !~ /^(\\/usr\\/sbin\\/nologin|\\/bin\\/false)$/) && (shadow[$1] !~ /^[!*]/ && shadow[$1] != \"\") {print $1}' /etc/shadow /etc/passwd"
    return execute_ssh_command(serveur, command)

# Get sudo directives from /etc/sudoers
def get_sudo_directives(serveur):
    return execute_ssh_command(serveur, "sudo grep -E '^Defaults' /etc/sudoers")

# Get non-privileged sudo users from /etc/sudoers
def get_non_privileged_sudo_users(serveur):
    return execute_ssh_command(serveur, "sudo grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\\(ALL.*\\)' | grep -Ev '(NOPASSWD|%sudo|root)'")

# Get negation operators in /etc/sudoers (e.g. the '!' symbol)
def get_negation_in_sudoers(serveur):
    return execute_ssh_command(serveur, "sudo grep -E '!' /etc/sudoers")

# Get strict sudo argument specifications from /etc/sudoers
def get_strict_sudo_arguments(serveur):
    result = execute_ssh_command(serveur, "sudo grep -E 'ALL=' /etc/sudoers | grep -E '*'")
    cleaned_elements = [element.replace("\t", " ") for element in result]
    return cleaned_elements

# Get sudoedit usage from /etc/sudoers for rule R44
def get_sudoedit_usage(serveur):
    sudoers_lines = execute_ssh_command(serveur, "sudo cat /etc/sudoers")
    violations = []
    sudoedit_used = []
    known_editors = ["vi", "vim", "nano", "emacs", "gedit", "kate"]
    
    for line in sudoers_lines:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        if "=" not in stripped_line:
            continue
        spec, cmd_part = stripped_line.split("=", 1)
        cmd_part = cmd_part.strip()
        if cmd_part.startswith("("):
            end_paren = cmd_part.find(")")
            if end_paren != -1:
                cmd_list_str = cmd_part[end_paren+1:].strip()
            else:
                cmd_list_str = cmd_part
        else:
            cmd_list_str = cmd_part
        commands = [cmd.strip() for cmd in cmd_list_str.split(",")]
        line_violation = False
        for cmd in commands:
            if cmd.upper() == "ALL":
                violations.append(f"\"{stripped_line}\" # The 'ALL' command allows execution of any command, which contradicts the requirement to use sudoedit for file editing.")
                line_violation = True
                break
            for editor in known_editors:
                if re.search(r'\b' + re.escape(editor) + r'\b', cmd) and "sudoedit" not in cmd:
                    violations.append(f"\"{stripped_line}\" # The command uses the editor '{editor}' without using sudoedit, which contradicts the requirement to use sudoedit for file editing.")
                    line_violation = True
                    break
            if line_violation:
                break
        # If no violation and the line uses 'sudoedit', record it.
        if not line_violation and "sudoedit" in stripped_line:
            sudoedit_used.append(stripped_line)
    return {"violations": violations, "sudoedit_usage": sudoedit_used}

# Get user private temporary directory configuration by checking PAM configuration
def get_user_private_tmp(serveur):
    files_to_check = ["/etc/pam.d/login", "/etc/pam.d/sshd"]
    results = []
    for f in files_to_check:
        try:
            output = execute_ssh_command(serveur, f"grep -Ei 'pam_namespace|pam_mktemp' {f}")
            if output:
                results.extend(output)
        except Exception as e:
            pass
    return results if results else None

# Iterate over all world-writable directories on the remote server and return a list of directories 
# that are accessible to everyone without the sticky bit set.
# For each found directory, verify:
#   - That it is indeed a directory (first character 'd').
#   - That the directory is world-writable (others have write permission).
#   - That its parent directory is accessible to everyone (others have execute permission).
#   - That the sticky bit is enabled.
#
# Only directories that are world-writable and accessible to everyone but without the sticky bit are added.
#
# Args:
#   serveur (paramiko.SSHClient): SSH connection to the remote server.
#
# Returns:
#   list: List of error messages for each non-compliant directory.
#         An empty list indicates that all world-writable directories accessible to everyone are compliant.
def check_all_sticky_bit(serveur):
    non_conformes = []
    # List all world-writable directories on the system
    find_cmd = "sudo find / -type d -perm -0002 -print 2>/dev/null"
    directories = execute_ssh_command(serveur, find_cmd)
    
    for directory in directories:
        directory = directory.strip()
        if not directory:
            continue

        # Try to retrieve the directory's permissions
        try:
            stat_cmd = f"stat -c '%A' {directory}"
            output = execute_ssh_command(serveur, stat_cmd)
        except Exception as e:
            output = []
        
        if not output:
            # If unable to retrieve permissions, check the parent directory first
            parent_dir = os.path.dirname(directory)
            try:
                parent_output = execute_ssh_command(serveur, f"stat -c '%A' {parent_dir}")
                if parent_output:
                    parent_permissions = parent_output[0].strip()
                    parent_others = parent_permissions[-3:]
                    # If the parent is not accessible (others lack execute permission), skip this directory
                    if parent_others[2] not in ['x', 't', 'T']:
                        continue
                else:
                    continue
            except Exception as e:
                continue
            # If parent's accessible but still no permission info for the directory,
            # add an error message.
            non_conformes.append(f"{directory}: Impossible de récupérer les permissions.")
            continue

        permissions = output[0].strip()

        # Check that it is indeed a directory
        if not permissions.startswith('d'):
            non_conformes.append(f"{directory}: Not a directory (permissions: {permissions}).")
            continue

        # Verify that the parent directory is accessible to everyone
        parent_dir = os.path.dirname(directory)
        parent_accessible = True
        try:
            parent_output = execute_ssh_command(serveur, f"stat -c '%A' {parent_dir}")
            if not parent_output:
                parent_accessible = False
            else:
                parent_permissions = parent_output[0].strip()
                parent_others = parent_permissions[-3:]
                if parent_others[2] not in ['x', 't', 'T']:
                    parent_accessible = False
            if not parent_accessible:
                continue
        except Exception as e:
            continue

        # Extract the permissions for "others" (last three characters)
        others = permissions[-3:]
        is_world_writable = others[1] == 'w'
        has_sticky_bit = others[2] in ['t', 'T']

        if is_world_writable and not has_sticky_bit:
            non_conformes.append(f"{directory}: World-writable without sticky bit (permissions: {permissions}).")
    
    return non_conformes

# Get secure file permissions (R50) by converting symbolic permissions to numeric
def get_secure_permissions(serveur, reference_data):
    reference_data = reference_data.get("R50", {}).get("expected", {})
    expected_files = {}
    for entry in reference_data:
        parts = entry.split()
        if len(parts) == 2:
            expected_files[parts[0]] = parts[1]
    output = execute_ssh_command(serveur, "sudo find / -type f -perm -0002 -ls 2>/dev/null")
    if isinstance(output, list):
        output = "\n".join(output)
    formatted_permissions = []
    for line in output.split("\n"):
        match = re.search(r"([bcdlsp-]?)([rwx-]{9})\s+\d+\s+(\w+)\s+(\w+)\s+\d+[, \d]*\s+\w+\s+\d+\s+[\d:]+\s+(.+)", line)
        if match:
            file_type, raw_permissions, owner, group, path = match.groups()
            if path in expected_files:
                def convert_to_numeric(perm):
                    mapping = {'r': 4, 'w': 2, 'x': 1, '-': 0}
                    u = sum(mapping[perm[i]] for i in range(0, 3))
                    g = sum(mapping[perm[i]] for i in range(3, 6))
                    o = sum(mapping[perm[i]] for i in range(6, 9))
                    return f"{u}{g}{o}"
                numeric_perm = convert_to_numeric(raw_permissions)
                expected_perm = expected_files[path]
                formatted_permissions.append(f"{owner} {group} {path} {numeric_perm} (expected: {expected_perm})")
    return formatted_permissions

# Get protected sockets and pipes
def get_protected_sockets(serveur):
    output = execute_ssh_command(serveur, r"sudo ss -xp | awk '{print $5}' | cut -d':' -f1 | sort -u | grep -vE '^\*$|^Local$' | xargs stat -c '%A %U %G %n'")
    if isinstance(output, list):
        output = "\n".join(output)
    protected_sockets = []
    directories = {}
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) == 4:
            permissions, owner, group, path = parts
            directory = os.path.dirname(path)
            if directory not in directories:
                dir_output = execute_ssh_command(serveur, f"stat -c '%A %U %G %n' {directory}")
                if isinstance(dir_output, list):
                    dir_permissions, dir_owner, dir_group, dir_path = "\n".join(dir_output).strip().split()
                else:
                    dir_permissions, dir_owner, dir_group, dir_path = dir_output.strip().split()
                directories[directory] = f"{dir_owner} {dir_group} {dir_path} {dir_permissions}"
                protected_sockets.append(f"{dir_owner} {dir_group} {dir_path} {dir_permissions}")
            protected_sockets.append(f"{owner} {group} {path} {permissions}")
    return protected_sockets

# Check PAM security for remote authentication (R67)
def check_pam_security(serveur, reference_data):
    expected_values = reference_data.get("R67", {}).get("expected", {})
    command_pam_auth = "grep -Ei 'pam_ldap' /etc/pam.d/* 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command_pam_auth)
    detected_pam_entries = stdout.read().decode().strip().split("\n")
    detected_pam_module = "pam_ldap" if detected_pam_entries and any("pam_ldap" in line for line in detected_pam_entries) else "Non trouvé"
    security_modules = expected_values.get("security_modules", {})
    detected_security_modules = {}
    for module in security_modules.keys():
        command = f"grep -E '{module}' /etc/pam.d/* 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_status = "Enabled" if stdout.read().decode().strip() else "Non trouvé"
        detected_security_modules[module] = detected_status
    detected_elements = {
        "detected_pam_modules": detected_pam_module,
        "security_modules": detected_security_modules
    }
    detected_list = [f"detected_pam_modules: {detected_elements['detected_pam_modules']}"]
    for module, detected_status in detected_elements["security_modules"].items():
        detected_list.append(f"{module}: {detected_status}")
    return detected_list

# Check access configuration for the /boot directory:
# - Verify if /boot is automatically mounted (based on /etc/fstab)
# - Retrieve the permissions, owner, and group of the /boot directory.
def check_boot_directory_access(serveur):
    detected_elements = {}

    # Check if /boot is automatically mounted
    auto_mount = execute_ssh_command(serveur, "grep -E '\\s/boot\\s' /etc/fstab | grep -v noauto")
    detected_elements["auto_mount"] = "auto" if auto_mount else "noauto"

    # Check permissions and owner of /boot
    boot_perm_info = execute_ssh_command(serveur, "stat -c '%a %U %G' /boot")
    if boot_perm_info:
        permissions, owner, group = boot_perm_info[0].split()
        detected_elements["permissions"] = str(permissions)
        detected_elements["owner"] = owner
    else:
        detected_elements["permissions"] = "Not Found"
        detected_elements["owner"] = "Not Found"

    return detected_elements

# Analyze access management on the server and generate a YAML report
def analyse_gestion_acces(serveur, niveau, reference_data):
    if reference_data is None:
        reference_data = {}
    report = {}
    rules = {
        "min": {
            "R30": (get_inactive_users, "Disable unused user accounts"),
            "R53": (find_orphan_files, "Avoid files or directories without a known user or group"),
            "R54": (check_all_sticky_bit, "Ensure sticky bit is set on world-writable directories"),
            "R56": (find_files_with_setuid_setgid, "Limit executables with setuid/setgid")
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
            "R67": (check_pam_security, "Secure remote authentication via PAM")
        },
        "renforce": {
            "R29": (check_boot_directory_access, "Restrict access to /boot directory")
        }
    }
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            if rule_id in ['R67', 'R50']:
                report[rule_id] = check_compliance(rule_id, function(serveur, reference_data), reference_data)
            else:
                report[rule_id] = check_compliance(rule_id, function(serveur), reference_data)
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"
    print(f"Checking paths: \nYAML: {yaml_path}\nHTML: {html_path}")
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100 if report else 0
    print(f"\nCompliance rate for niveau {niveau.upper()}: {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)
    
# Save the analysis report in YAML format to the specified directory
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        file.write("gestion_acces:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            # For R44, format detected_elements manually
            if rule_id == "R44" and isinstance(content.get("detected_elements"), dict):
                file.write(f"    apply: {str(content.get('apply')).lower()}\n")
                file.write(f"    status: {content.get('status')}\n")
                file.write("    detected_elements:\n")
                # Write violations
                file.write("      violations:\n")
                if content["detected_elements"]["violations"]:
                    for violation in content["detected_elements"]["violations"]:
                        file.write(f"        - {violation}\n")
                else:
                    file.write("        - None\n")
                # Write sudoedit usage info
                file.write("      sudoedit_usage:\n")
                if content["detected_elements"]["sudoedit_usage"]:
                    for usage in content["detected_elements"]["sudoedit_usage"]:
                        file.write(f"        - {usage}\n")
                else:
                    file.write("        - None\n")
            else:
                yaml_content = yaml.safe_dump(content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False)
                indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
                file.write(indented_yaml + "\n")
        file.write("\n")
    print(f"Report generated: {output_path}")
