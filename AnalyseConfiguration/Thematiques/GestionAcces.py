import yaml
import os
import paramiko
import re
from GenerationRapport.GenerationRapport import generate_html_report

def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

def check_compliance(rule_id, detected_values, reference_data):
    if rule_id == 'R44':
        violations = detected_values.get("violations") if detected_values else None
        is_non_compliant = bool(violations)  
        return {
            "apply": not is_non_compliant,  
            "status": "Non-Compliant" if is_non_compliant else "Compliant",
            "detected_elements": detected_values if is_non_compliant else "None"
        }
    elif rule_id == 'R52':
        expected_list = reference_data.get(rule_id, {}).get("expected", [])
        expected_dict = {}
        for entry in expected_list:
            parts = entry.split()
            if len(parts) == 2:
                expected_dict[parts[0]] = parts[1]

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
        pam_info = detected_values.get("pam_namespace", {})
        activated = pam_info.get("activated", False)
        configured = pam_info.get("configured", False)
        is_compliant = activated and configured
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "detected_elements": {
                "pam_namespace": {
                    "activated": activated,
                    "configured": configured
                }
            }
        }
    elif rule_id == 'R67':
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
    elif rule_id == 'R41':
        expected_values = reference_data.get('R41', {}).get('expected', {}).get('noexec_commands', [])
        if not detected_values:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": expected_values,
                "detected_elements": "None"
            }
        detected_set = set(detected_values)
        expected_set = set(expected_values)
        if detected_values and set(detected_values) == set(expected_values):
            return {
                "apply": True,
                "status": "Compliant",
                "expected_elements": expected_values,
                "detected_elements": detected_values
            }
        else:
            unexpected_elements = list(set(detected_values) - set(expected_values))
            missing_elements = list(set(expected_values) - set(detected_values))
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": expected_values,
                "detected_elements": detected_values,
                "unexpected_elements": unexpected_elements or None,
                "missing_elements": missing_elements or None
            }
    elif rule_id == 'R56':
        expected_list = reference_data.get('R56', {}).get("expected", [])
        print(expected_list)
        detected_filtered = [item for item in detected_values if item not in expected_list] if detected_values else []
        is_compliant = len(detected_filtered) == 0  
        return {
            "apply": is_compliant,
            "status": "Compliant" if is_compliant else "Non-Compliant",
            "expected_elements": expected_list if expected_list else "None",
            "detected_elements": detected_filtered if detected_filtered else "None"
        }
    elif rule_id == 'R57':
        expected_execs = set(reference_data.get('R57', {}).get('expected', []))
        detected_execs = set(detected_values) if detected_values else set()
        unauthorized_execs = detected_execs - expected_execs
        if unauthorized_execs:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": sorted(list(expected_execs)),
                "detected_elements": sorted(list(detected_execs)),
                "unauthorized_elements": sorted(list(unauthorized_execs))
            }
        else:
            return {
                "apply": True,
                "status": "Compliant",
                "detected_elements": sorted(list(detected_execs)) or "None"
            }
    elif rule_id == 'R64':
        expected_services = set(reference_data.get('R64', {}).get('expected', []))
        detected_services = set(detected_values or [])
        unauthorized_services = detected_services - expected_services
        if unauthorized_services:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": list(expected_services),
                "detected_elements": list(detected_services),
                "unauthorized_elements": list(unauthorized_services)
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

def save_yaml_report(data, output_file, rules, niveau):
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        file.write("access_management:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, ("", ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            if rule_id == "R44" and isinstance(content.get("detected_elements"), dict):
                file.write(f"    apply: {str(content.get('apply')).lower()}\n")
                file.write(f"    status: {content.get('status')}\n")
                file.write("    detected_elements:\n")
                file.write("      violations:\n")
                if content["detected_elements"]["violations"]:
                    for violation in content["detected_elements"]["violations"]:
                        file.write(f"        - {violation}\n")
                else:
                    file.write("        - None\n")
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

# --- Functions that execute commands are adapted to take os_info and branch accordingly ---
def get_standard_users(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return set(execute_ssh_command(serveur, "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"))
    else:
        print("[get_standard_users] Non-Ubuntu OS detected; standard users not retrieved.")
        return set()

def get_recent_users(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return set(execute_ssh_command(serveur, "last -w -s -60days -F | awk '{print $1}' | grep -v 'wtmp' | sort | uniq"))
    else:
        print("[get_recent_users] Non-Ubuntu OS detected; recent users not retrieved.")
        return set()

def get_disabled_users(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return set(execute_ssh_command(serveur, "sudo awk -F: '($2 ~ /^!|^\\*/) {print $1}' /etc/shadow"))
    else:
        print("[get_disabled_users] Non-Ubuntu OS detected; disabled users not retrieved.")
        return set()

def get_inactive_users(serveur, os_info):
    return list((get_standard_users(serveur, os_info) - get_recent_users(serveur, os_info)) - get_disabled_users(serveur, os_info))

def find_orphan_files(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return execute_ssh_command(serveur, "sudo find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null")
    else:
        print("[find_orphan_files] Non-Ubuntu OS detected; orphan files search skipped.")
        return []

def find_files_with_setuid_setgid(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        ro_mounts = execute_ssh_command(serveur, "findmnt -r -n -o TARGET")

        # Construire les exclusions (lecture seule et /usr/bin/sudo)
        exclusions = " ".join([f"-path '{mount}/*' -prune -o" for mount in ro_mounts])
        exclusions += " -path '/usr/bin/sudo' -prune -o"

        # Construire la commande find avec exclusions
        find_command = f"find / {exclusions} -type f -perm /6000 -print 2>/dev/null"

        # Exécuter la commande sur le serveur
        return execute_ssh_command(serveur, find_command)
    else:
        print("[find_files_with_setuid_setgid] Non-Ubuntu OS detected; search skipped.")
        return []

def get_service_accounts(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = ("sudo awk -F: 'FNR==NR { shadow[$1]=$2; next } "
                   "($3 < 1000 && $3 != 0) && ($7 !~ /^(\\/usr\\/sbin\\/nologin|\\/bin\\/false)$/) "
                   "&& (shadow[$1] !~ /^[!*]/ && shadow[$1] != \"\") {print $1}' /etc/shadow /etc/passwd")
        return execute_ssh_command(serveur, command)
    else:
        print("[get_service_accounts] Non-Ubuntu OS detected; service accounts not retrieved.")
        return []

def get_sudo_directives(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return execute_ssh_command(serveur, "sudo grep -E '^Defaults' /etc/sudoers")
    else:
        print("[get_sudo_directives] Non-Ubuntu OS detected; sudo directives not retrieved.")
        return []

def get_non_privileged_sudo_users(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return execute_ssh_command(serveur, "sudo grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\\(ALL.*\\)' | grep -Ev '(NOPASSWD|%sudo|root)'")
    else:
        print("[get_non_privileged_sudo_users] Non-Ubuntu OS detected; non-privileged sudo users not retrieved.")
        return []

def get_negation_in_sudoers(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        return execute_ssh_command(serveur, "sudo grep -E '^[^#].*!' /etc/sudoers")
    else:
        print("[get_negation_in_sudoers] Non-Ubuntu OS detected; negation operators not retrieved.")
        return []

def get_strict_sudo_arguments(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        result = execute_ssh_command(serveur, "sudo grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\*'")
        cleaned_elements = [element.replace("\t", " ") for element in result]
        return cleaned_elements
    else:
        print("[get_strict_sudo_arguments] Non-Ubuntu OS detected; strict sudo arguments not retrieved.")
        return []

def get_sudoedit_usage(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
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
                    violations.append(f"\"{stripped_line}\" # Uses ALL, which contradicts sudoedit use.")
                    line_violation = True
                    break
                for editor in known_editors:
                    if re.search(r'\b' + re.escape(editor) + r'\b', cmd) and "sudoedit" not in cmd:
                        violations.append(f"\"{stripped_line}\" # Uses editor '{editor}' without sudoedit.")
                        line_violation = True
                        break
                if line_violation:
                    break
            if not line_violation and "sudoedit" in stripped_line:
                sudoedit_used.append(stripped_line)
        return {"violations": violations, "sudoedit_usage": sudoedit_used}
    else:
        print("[get_sudoedit_usage] Non-Ubuntu OS detected; sudoedit usage not retrieved.")
        return {"violations": [], "sudoedit_usage": []}

def get_user_private_tmp(serveur, os_info):
    result = {
        "pam_namespace": {
            "activated": False,
            "configured": False
        }
    }

    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        # Check if pam_namespace is enabled in PAM configuration files
        for pam_file in ["/etc/pam.d/login", "/etc/pam.d/sshd"]:
            try:
                output = execute_ssh_command(serveur, f"grep -Ei 'pam_namespace' {pam_file}")
                if output:
                    result["pam_namespace"]["activated"] = True
                    break
            except Exception as e:
                print(f"[get_user_private_tmp] Error reading PAM file '{pam_file}': {e}")
                # Continue the loop even if an error occurred

        # Check if namespace.conf is properly configured
        try:
            output = execute_ssh_command(serveur, "grep -Ev '^\s*#|^\s*$' /etc/security/namespace.conf")
            if output:
                result["pam_namespace"]["configured"] = True
        except Exception as e:
            print(f"[get_user_private_tmp] Error reading namespace.conf: {e}")

        return result
    else:
        print("[get_user_private_tmp] Non-Ubuntu OS detected; skipping check.")
        return result



def check_all_sticky_bit(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        non_conformes = []
        find_cmd = "sudo find / -type d -perm -0002 -print 2>/dev/null"
        directories = execute_ssh_command(serveur, find_cmd)
        for directory in directories:
            directory = directory.strip()
            if not directory:
                continue
            try:
                stat_cmd = f"stat -c '%A' {directory}"
                output = execute_ssh_command(serveur, stat_cmd)
            except Exception:
                output = []
            if not output:
                parent_dir = os.path.dirname(directory)
                try:
                    parent_output = execute_ssh_command(serveur, f"stat -c '%A' {parent_dir}")
                    if parent_output:
                        parent_permissions = parent_output[0].strip()
                        parent_others = parent_permissions[-3:]
                        if parent_others[2] not in ['x', 't', 'T']:
                            continue
                    else:
                        continue
                except Exception:
                    continue
                non_conformes.append(f"{directory}: Unable to retrieve permissions.")
                continue
            permissions = output[0].strip()
            if not permissions.startswith('d'):
                non_conformes.append(f"{directory}: Not a directory (permissions: {permissions}).")
                continue
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
            except Exception:
                continue
            others = permissions[-3:]
            is_world_writable = others[1] == 'w'
            has_sticky_bit = others[2] in ['t', 'T']
            if is_world_writable and not has_sticky_bit:
                non_conformes.append(f"{directory}: World-writable without sticky bit (permissions: {permissions}).")
        return non_conformes
    else:
        print("[check_all_sticky_bit] Non-Ubuntu OS detected; sticky bit check skipped.")
        return []

def get_secure_permissions(serveur, reference_data, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        ref_data = reference_data.get("R50", {}).get("expected", {})
        expected_files = {}
        for entry in ref_data:
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
    else:
        print("[get_secure_permissions] Non-Ubuntu OS detected; secure permissions check skipped.")
        return []

def get_protected_sockets(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
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
                    if isinstance(dir_output, list) and dir_output:
                        dir_permissions, dir_owner, dir_group, dir_path = "\n".join(dir_output).strip().split()
                    else:
                        continue
                    directories[directory] = f"{dir_owner} {dir_group} {dir_path} {dir_permissions}"
                    protected_sockets.append(f"{dir_owner} {dir_group} {dir_path} {dir_permissions}")
                protected_sockets.append(f"{owner} {group} {path} {permissions}")
        return protected_sockets
    else:
        print("[get_protected_sockets] Non-Ubuntu OS detected; protected sockets not retrieved.")
        return []

def check_boot_directory_access(serveur, reference_data, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        detected_elements = {}
        auto_mount = execute_ssh_command(serveur, "grep -E '\\s/boot\\s' /etc/fstab | grep -v noauto")
        detected_elements["auto_mount"] = "auto" if auto_mount else "noauto"
        boot_perm_info = execute_ssh_command(serveur, "stat -c '%a %U %G' /boot")
        if boot_perm_info:
            permissions, owner, group = boot_perm_info[0].split()
            detected_elements["permissions"] = permissions
            detected_elements["owner"] = owner
        else:
            detected_elements["permissions"] = "Not Found"
            detected_elements["owner"] = "Not Found"
        expected = reference_data.get('R29', {}).get('expected', {})
        return None if detected_elements == expected else detected_elements
    else:
        print("[check_boot_directory_access] Non-Ubuntu OS detected; boot directory access check skipped.")
        return None

def check_sudo_group_restriction(serveur, reference_data, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        detected_elements = {}
        sudo_stat = execute_ssh_command(serveur, "stat -c '%a %U %G' /usr/bin/sudo")
        if sudo_stat:
            perms, owner, group = sudo_stat[0].split()
            detected_elements["permissions"] = perms
            detected_elements["owner"] = owner
            detected_elements["group"] = group
        else:
            detected_elements["permissions"] = "Not Found"
            detected_elements["owner"] = "Not Found"
            detected_elements["group"] = "Not Found"
        expected = reference_data.get('R38', {}).get('expected', {})
        return None if detected_elements == expected else detected_elements
    else:
        print("[check_sudo_group_restriction] Non-Ubuntu OS detected; sudo group restriction check skipped.")
        return None

def check_sudo_noexec_commands(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        detected_elements = []
        defaults_noexec = execute_ssh_command(serveur, "grep -E '^[^#]*Defaults[[:space:]]+NOEXEC' /etc/sudoers")
        if defaults_noexec:
            detected_elements.extend(defaults_noexec)
        cmnd_alias_noexec = execute_ssh_command(serveur, "grep -E '^[^#]*Cmnd_Alias[[:space:]]+NOEXEC_CMDS' /etc/sudoers")
        if cmnd_alias_noexec:
            detected_elements.extend(cmnd_alias_noexec)
        noexec_alias_usage = execute_ssh_command(serveur, "grep -E '^[^#]*NOEXEC_CMDS' /etc/sudoers | grep -v 'Cmnd_Alias'")
        if noexec_alias_usage:
            detected_elements.extend(noexec_alias_usage)
        return detected_elements or None
    else:
        print("[check_sudo_noexec_commands] Non-Ubuntu OS detected; sudo noexec check skipped.")
        return None

def check_setuid_setgid_root(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -user root -type f 2>/dev/null"
        return execute_ssh_command(serveur, command)
    else:
        print("[check_setuid_setgid_root] Non-Ubuntu OS detected; setuid/setgid check skipped.")
        return None

def check_service_privileges(serveur, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "ps -eo user:20,cmd --no-header | awk '$1==\"root\" {print $2}' | sort -u"
        return execute_ssh_command(serveur, command)
    else:
        print("[check_service_privileges] Non-Ubuntu OS detected; service privileges check skipped.")
        return None

# --- analyse_gestion_acces calls the above functions ---
def analyse_gestion_acces(serveur, niveau, reference_data, os_info):
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
        },
        "renforce": {
            "R29": (check_boot_directory_access, "Restrict access to /boot directory"),
            "R38": (check_sudo_group_restriction, "Restrict sudo to a dedicated group"),
            "R41": (check_sudo_noexec_commands, "Check sudo directives using NOEXEC"),
            "R57": (check_setuid_setgid_root, "Avoid executables with setuid root and setgid root"),
            "R64": (check_service_privileges, "Configure services with minimal privileges")
        }
    }
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {comment}")
            # Pour certaines règles, la fonction attend (serveur, reference_data, os_info)
            if rule_id in ['R67', 'R50', 'R29', 'R38']:
                report[rule_id] = check_compliance(rule_id, function(serveur, reference_data, os_info), reference_data)
            else:
                report[rule_id] = check_compliance(rule_id, function(serveur, os_info), reference_data)
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"
    compliance_percentage = (sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100) if report else 0
    print(f"\nCompliance rate for niveau {niveau.upper()}: {compliance_percentage:.2f}%")

    generate_html_report(yaml_path, html_path, niveau)

    html_yaml_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.yml"

    if os.path.exists(html_yaml_path):
        os.remove(html_yaml_path)
