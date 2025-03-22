import yaml
import os

#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"


def execute_ssh_command(serveur, command):
    """Exécute une commande SSH sur le serveur distant et retourne la sortie."""
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

"""

Mettre a jour les fichiers apres l'analyse apres l'application

"""
def update (application_file , analyse_file , thematique , rule ) : 
    # Mise a jour dans le fichier d'application 
    with open(application_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Compliant'
    with open(application_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)
    
    # Mise a jour dans le fichier d'analyse 
    with open(analyse_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = True
    data[thematique][rule]['status'] = 'Compliant'
    with open(analyse_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def update_report(level , thematique ,  rule, clear_keys=[]):
    
    if level == 'min' : 
        update(application_min , analyse_min , thematique , rule)
    elif level ==  'moyen' :
        update(application_moyen , analyse_moyen , thematique , rule)

def apply_r30(serveur, report):

    r30_data = report.get("R30", {})
    if not r30_data.get("apply", False):
        print("- R30: No action required.")
        return "Compliant"
    inactive_users = r30_data.get("detected_elements", [])
    if not inactive_users or inactive_users == "None":
        print("- No unused accounts to disable.")
        return "Compliant"
    for user in inactive_users:
        print(f"- Disabling account {user}...")
        execute_ssh_command(serveur, f'sudo passwd -l {user}')
    
    print("- R30: All inactive accounts have been disabled.")
    update_report('min', 'access_management', 'R30')

def apply_r53(serveur, report):

    r53_data = report.get("R53", {})
    if not r53_data.get("apply", False):
        print("- R53: No action required.")
        return "Compliant"
    orphan_files = r53_data.get("detected_elements", [])
    if not orphan_files or orphan_files == "None":
        print("- No orphaned files detected.")
        return "Compliant"
    for file_path in orphan_files:
        print(f"- Assigning file {file_path} to root...")
        execute_ssh_command(serveur, f"sudo chown root:root {file_path}")
    
    print("- R53: All orphaned files have been corrected.")
    update_report('min', 'access_management', 'R53')

def apply_r56(serveur, report):

    r56_data = report.get("R56", {})
    if not r56_data.get("apply", False):
        print("- R56: No action required.")
        return "Compliant"

    dangerous_files = r56_data.get("detected_elements", [])
    if not dangerous_files or dangerous_files == "None":
        print("- No problematic setuid/setgid files detected.")
        return "Compliant"

    for file_path in dangerous_files:
        print(f"- Removing setuid/setgid permissions on {file_path}...")
        execute_ssh_command(serveur, f"sudo chmod -s {file_path}")

    print("- R56: All dangerous files have been secured.")
    update_report('min', 'access_management', 'R56')


def apply_R34(serveur, report):

    r34_data = report.get("R34", {})

    if not r34_data.get("apply", False):
        print("- R34: No action required.")
        return "Compliant"

    r34_detected_elements = r34_data.get("R34", {}).get("detected_elements", [])
    
    for compte in r34_detected_elements:
        execute_ssh_command(serveur, f"sudo passwd -l {compte}")

    print("- R34: Inactive accounts have been successfully disabled.")
    update_report('moyen', 'access_management', 'R34')


def apply_R39(serveur, report):

    r39_data = report.get("R39", {})

    if not r39_data.get("apply", False):
        print("- R39: No action required.")
        return "Compliant"

    # Hardcoded list of expected directives
    directives_expected = [
        "Defaults noexec",
        "Defaults requiretty",
        "Defaults use_pty",
        "Defaults umask=0027",
        "Defaults ignore_dot",
        "Defaults env_reset"
    ]

    r39_detected_elements = r39_data.get("detected_elements", [])

    # Backup sudoers file if not already done
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    # Simple normalization of detected directives (removing tabs/spaces)
    normalized_detected = ['\t'.join(line.split()) for line in r39_detected_elements]

    for line in normalized_detected:
        if line not in directives_expected:
            escaped_line = line.replace(" ", "[[:space:]]*")
            sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
            execute_ssh_command(serveur, sed_command)

    print("- R39: Non-compliant sudoers directives commented successfully.")
    update_report('moyen', 'access_management', 'R39')


"""
The application of rule R40 aims to restrict sudo access to only authorized users,
such as root, ubuntu, administrator, and %admin, while preserving specific privileges
for other users with restrictions on certain commands. If an unauthorized user has
full sudo privileges (ALL), these privileges are revoked. However, if a user has
specific restrictions (e.g., access to /usr/bin/apt), their configuration is preserved.
The /etc/sudoers file is modified accordingly, and a report is updated to reflect
compliance status.
"""

def apply_R40(serveur, report):

    r40_data = report.get("R40", {})
    if not r40_data.get("apply", False):
        print("- R40: No action required.")
        return "Compliant"

    r40_detected_elements = r40_data.get("detected_elements", [])

    # Backup the sudoers file before making changes if not already done
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r40_detected_elements:
        # Prepare the line for flexible search in sudoers (tabs/spaces)
        escaped_line = line.replace(" ", "[[:space:]]*")
        sed_command = f"sudo sed -i 's|^[[:space:]]*{escaped_line}$|# &|' /etc/sudoers"
        execute_ssh_command(serveur, sed_command)

    print("- R40: Non-privileged sudo entries have been successfully commented.")
    update_report('moyen', 'access_management', 'R40')

# Rule R42
def apply_R42(serveur, report):
    r42_data = report.get("R42", {})

    if not r42_data.get("apply", False):
        print("- R42: No action required.")
        return "Compliant"

    r42_detected_elements = r42_data.get("detected_elements", [])

    if not r42_detected_elements:
        print("- R42: No negation operators detected.")
        update_report('min', 'access_management', 'R42')
        return "Compliant"

    # Backup the sudoers file before making changes if not already done
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r42_detected_elements:
        escaped_line = line.replace(" ", "[[:space:]]*")
        sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
        execute_ssh_command(serveur, sed_command)

    print("- R42: Lines containing negation operators have been successfully commented.")
    update_report('moyen', 'access_management', 'R42')

def apply_R43(serveur, report):

    r43_data = report.get("R43", {})

    if not r43_data.get("apply", False):
        print("- R43: No action required.")
        return "Compliant"

    r43_detected_elements = r43_data.get("detected_elements", [])

    # Backup the sudoers file before making changes if not already done
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r43_detected_elements:
        if not line.startswith("#"):
            escaped_line = line.replace(" ", "[[:space:]]*")
            sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
            execute_ssh_command(serveur, sed_command)

    print("- R43: Sudo lines without strict argument specification have been successfully commented.")
    update_report('moyen', 'access_management', 'R43')


def apply_R44(serveur, report):

    r44_data = report.get("R44", {})

    if not r44_data.get("apply", False):
        print("- R44: No action required.")
        return "Compliant"

    r44_detected_elements = r44_data.get("detected_elements", {}).get("sudoedit_usage", [])
    
    # Backup the sudoers file before making changes if not already done
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r44_detected_elements:
        if not line.startswith("#"):
            escaped_line = line.replace(" ", "[[:space:]]*")
            sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
            execute_ssh_command(serveur, sed_command)

    print("- R44: Lines with configuration violations for sudoedit have been successfully commented.")
    update_report('moyen', 'access_management', 'R44')


def apply_R50(serveur, report):

    """Applies rule R50 by verifying and modifying permissions for sensitive files."""
    # Define reference_data as a dictionary
    reference_data = {
        "description": "Restrict access permissions to sensitive files and directories",
        "expected": [
            "/etc/shadow 600",
            "/etc/passwd 644",
            "/etc/group 644",
            "/etc/gshadow 600",
            "/etc/ssh/sshd_config 600",
            "/root/ 700",
            "/var/log/auth.log 640",
            "/var/log/syslog 640",
            "/var/log/secure 640",
            "/etc/cron.d 750",
            "/etc/cron.daily 750",
            "/etc/cron.hourly 750",
            "/etc/cron.monthly 750",
            "/etc/cron.weekly 750",
            "/etc/fstab 644",
            "/etc/securetty 600",
            "/etc/security/limits.conf 644",
            "/boot/grub/grub.cfg 600",
        ],
    }

    # Parse the reference_data to create expected_permissions dictionary
    expected_permissions = {
        entry.rsplit(" ", 1)[0]: entry.rsplit(" ", 1)[1]
        for entry in reference_data.get("expected", [])
    }
    r50_data = report.get("R50", {})

    if not r50_data.get("apply", False):
        print("- R50: No action required.")
        return "Compliant"
      
    print("\n    Applying rule 50 (Restrict access permissions to sensitive files and directories)    \n")
    
    # Retrieve detected elements
    detected_elements = r50_data.get("detected_elements", [])

    if not detected_elements:            
        print("Rule 50: No elements detected for insecure file editing.")
        return

    # List of modified files
    all_files_modified = []

    # Apply expected permissions
    for file_path in detected_elements:
        file_name = file_path.split(" ")[2]

        if file_name in expected_permissions:
            # Modify permissions
            chmod_command = f"sudo chmod {expected_permissions[file_name]} {file_name}"
            serveur.exec_command(chmod_command)
            all_files_modified.append(file_path)

    update_report('moyen', 'access_management', 'R50') 


def apply_R52(serveur, report):
    """Applies rule R52 by verifying and modifying permissions for named pipes and sockets."""
    print("\n  Applying rule 52 (Protect named pipes and sockets)    \n")

    r52_data = report.get("R52", {})
    # Retrieve expected permissions from the reference data
    expected_permissions = {
        entry.rsplit(" ", 1)[0]: entry.rsplit(" ", 1)[1]
        for entry in r52_data.get("expected_elements", [])
    }

    if not r52_data.get("apply", False):
        print("- R52: No action required.")
        return "Compliant"
    
    # Detection of elements in the report
    detected_elements = r52_data.get("differences", [])

    if not detected_elements:
        print("Rule 52: No elements detected for permission change.")
        return

    # List of modified elements
    all_elements_modified = []

    # Apply expected permissions
    for element in detected_elements:
        file_path = element.split()[0]
        if file_path in expected_permissions:
            # Modify permissions
            chmod_command = f"sudo chmod {expected_permissions[file_path]} {file_path}"
            serveur.exec_command(chmod_command)
            all_elements_modified.append(file_path)

    update_report('moyen', 'access_management', 'R52') 
    print("Rule 52 successfully applied, and the report updated.")


def apply_R55(serveur, report):
    """
    Applies rule R55: Isolation of user temporary directories.
    - Checks if 'apply' is True.
    - Backs up detected directories.
    - Mounts directories with security options.
    """
    # Check if the rule is activated
    if report.get("access_management", {}).get("R55", {}).get("apply", True): 
        # Retrieve rule R55 from the report
        detected_elements = report.get("access_management", {}).get("R55", {}).get("detected_elements", [])
        # Check if elements were detected
        if not detected_elements:
            print("   Rule 55: No elements detected for isolation.")
            return

        # Apply actions for each detected directory
        for file_path in detected_elements:
            # Check if the path is a directory or file
            is_directory_command = f"test -d {file_path} && echo 'directory' || echo 'file'"
            stdin, stdout, stderr = serveur.exec_command(is_directory_command)
            is_directory = stdout.read().decode().strip()

            # Backup before modification (only if not already backed up)
            backup_command = f"sudo cp -r --no-clobber {file_path} {file_path}.htms"

            # Apply isolation (secure mount) depending on whether it's a directory or file
            if is_directory == "directory":
                mount_command = f"sudo mount -o bind,noexec,nodev,nosuid {file_path} {file_path}"
            else:
                mount_command = f"echo '{file_path} is a file, no mount applied.'"

            # Execute commands
            for cmd in [backup_command, mount_command]:
                stdin, stdout, stderr = serveur.exec_command(cmd)
                print(stdout.read().decode(), stderr.read().decode())

        print("- Rule 55 successfully applied, and the report updated.")


def apply_R67(serveur, report):

    """Applies rule R67 to secure PAM authentication."""
    r67_data = report.get("R67", {})

    if not r67_data.get("apply", False):
        print("- R67: No action required.")
        return "Compliant"

    print("\n Applying rule R67 (Securing PAM authentication)\n")

    # List of expected rules derived from reference
    pam_rules = [
        "account required pam_nologin.so",
        "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close",
        "session required pam_loginuid.so",
        "session optional pam_keyinit.so force revoke",
        "session optional pam_motd.so motd=/run/motd.dynamic",
        "session optional pam_motd.so noupdate",
        "session optional pam_mail.so standard noenv # [1]",
        "session required pam_limits.so",
        "session required pam_env.so # [1]",
        "session required pam_env.so user_readenv=1 envfile=/etc/default/locale",
        "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open",
        "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=300",
        "auth required pam_faillock.so authfail audit deny=5 unlock_time=300",
        "auth optional pam_pwquality.so retry=3 minlen=12 difok=2"
    ]

    # Backup PAM files before modification
    execute_ssh_command(serveur, "sudo cp -rn /etc/pam.d /etc/pam.d.bak_R67")

    # Apply missing rules in the common file (/etc/pam.d/common-auth for example)
    pam_target_file = "/etc/pam.d/common-auth"

    for rule in pam_rules:
        # Check if the rule is already present
        grep_cmd = f"sudo grep -qF \"{rule}\" {pam_target_file} && echo FOUND || echo NOTFOUND"
        rule_present = execute_ssh_command(serveur, grep_cmd)

        if "NOTFOUND" in rule_present[0]:  # Check the first element of the returned list
            # Append the rule at the end of the file if not present
            append_cmd = f"echo \"{rule}\" | sudo tee -a {pam_target_file} > /dev/null"
            execute_ssh_command(serveur, append_cmd)
            print(f"Rule added: {rule}")
        else:
            print(f"Rule already present: {rule}")

    # Update the report
    update_report('moyen', 'access_management', 'R67')
    print("- R67: PAM security rules have been successfully applied.")


def apply_access_management(serveur, niveau, report_data):
    """Applies access management rules based on the specified level."""
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("access_management", None)
    if apply_data is None: 
        return 
    
    rules = {
        "min": {
            "R30": (apply_r30, "Deactivate unused user accounts"),
            "R53": (apply_r53, "Fix files without owner/group"),
            "R56": (apply_r56, "Remove unnecessary setuid/setgid")
        },
        "moyen": {            
            "R34": (apply_R34, "Disable service accounts (non-exhaustive list)"),
            "R39": (apply_R39, "Modify sudo configuration directives"),
            "R40": (apply_R40, "Use non-privileged target users for sudo commands"),
            "R42": (apply_R42, "Ban negations in sudo specifications"),
            "R43": (apply_R43, "Specify arguments in sudo specifications"),
            "R44": (apply_R44, "Edit files securely with sudo"),
            "R50": (apply_R50, "Restrict access permissions to sensitive files and directories"),
            "R52": (apply_R52, "Ensure named pipes and sockets have restricted permissions"),
            "R55": (apply_R55, "Isolate user temporary directories"),
            "R67": (apply_R67, "Ensure remote authentication via PAM")
        },
        "avancé": {
            # To be completed as needed
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, None): 
                print(f"-> Applying rule {rule_id}: {comment}")
                function(serveur, apply_data)

    print(f"\n- Corrections applied - ACCESS MANAGEMENT - Level {niveau.upper()}")
