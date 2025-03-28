import yaml
import os

#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"

application_renforce = "./GenerationRapport/RapportApplication/application_renforce.yml"
analyse_renforce = "./GenerationRapport/RapportAnalyse/analyse_renfore.yml"

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
    elif level ==  'renforce' :
        update(application_renforce , analyse_renforce , thematique , rule)

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
        print(f"sudo chmod -s {file_path}")
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


#######################################################################################
#                                                                                     #
#                        Gestion d'acces niveau renforcé                              #
#                                                                                     #
#######################################################################################
#Regle 29 (NB pas de boot sur les vm donc valide pour les hoste)
def apply_R29(serveur, report):
    """Applique la règle R29 en restreignant l'accès au répertoire /boot et en modifiant /etc/fstab en toute sécurité."""

    reference_data = {
        "description": "Restrict access to /boot directory.",
        "expected": {
            "auto_mount": "noauto",
            "permissions": "700",
            "owner": "root",
        },
    }

    r29_data = report.get("access_management", {}).get("R29", {})

    if not r29_data.get("apply", False):
        print("- R29: No action required.")
        return "Compliant"

    print("\n    Applying rule R29 (Restrict access to /boot directory)    \n")

    # Vérifier les éléments détectés
    detected_elements = r29_data.get("detected_elements", {})

    if not detected_elements:
        print("Rule R29: No elements detected for insecure /boot configuration.")
        return

    # Travailler sur une copie temporaire avant toute modification définitive
    print("\n🔹 Création d'une copie temporaire de /etc/fstab...")
    serveur.exec_command("sudo cp /etc/fstab /tmp/fstab.tmp_htms")

    # Détecter automatiquement le périphérique /boot
    command = "sudo lsblk -o NAME,UUID,MOUNTPOINT | grep ' /boot$' | awk '{gsub(/^[├└─ ]*/, \"\", $1); gsub(/^[├└─ ]*/, \"\", $2); print \"/dev/\" $1, $2}'"
    _, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip()
    #output="/dev/sda-test uuid_test"  # Simulé pour test

    if output:
        device, device_uuid = output.split()
        print(f"🔹 Périphérique de /boot détecté : {device} avec UUID : {device_uuid}")
    else:
        print("❌ Aucun périphérique de /boot détecté.")
        return "Failed"

    # Vérifier si UUID ou device sont déjà dans /etc/fstab
    _, stdout, stderr = serveur.exec_command(f"grep -E '({device_uuid}|{device})' /tmp/fstab.tmp_htms")
    fstab_entry = stdout.read().decode().strip()

    if fstab_entry:
        print(f"🔹 Une entrée existante pour {device} ou {device_uuid} est présente dans /etc/fstab.")
        # Mise à jour en supprimant l'ancienne entrée
        serveur.exec_command(f"grep -Ev '({device_uuid}|{device})' /tmp/fstab.tmp_htms | sudo tee /tmp/fstab.tmp_htms > /dev/null")
    else:
        print(f"🔹 Aucune entrée pour {device} ou {device_uuid} dans /etc/fstab.")

    # Ajouter la ligne correcte avec noauto
    serveur.exec_command(f"echo 'UUID={device_uuid} /boot ext4 defaults,noauto 0 2' | sudo tee -a /tmp/fstab.tmp_htms > /dev/null")

    # Vérification de la syntaxe
    _, stdout, stderr = serveur.exec_command("sudo mount -a -T /tmp/fstab.tmp_htms")

    if stdout.channel.recv_exit_status() == 0:
        print("✅ Syntaxe valide. Sauvegarde et application des modifications.")
        serveur.exec_command("sudo cp /etc/fstab /etc/fstab.back_R29")
        serveur.exec_command("sudo mv /tmp/fstab.tmp_htms /etc/fstab")
        serveur.exec_command("sudo mount -o remount /boot")

        # Vérifier et corriger les permissions de /boot
        print("\n🔹 Vérification des permissions de /boot...")
        if detected_elements.get("permissions") != reference_data["expected"]["permissions"]:
            serveur.exec_command("sudo chmod 700 /boot")
            print("✅ Permissions de /boot corrigées.")

        if detected_elements.get("owner") != reference_data["expected"]["owner"]:
            serveur.exec_command("sudo chown root:root /boot")
            print("✅ Propriétaire de /boot corrigé.")

        # Update the report
        update_report('renforce', 'access_management', 'R29')
        print("✅ R29 appliquée avec succès.")
       
    else:
        print("❌ Erreur de syntaxe. Restauration de l'original.")
        serveur.exec_command("sudo rm /tmp/fstab.tmp_htms")
        return "Failed"


###Regle 38
def apply_R38(serveur, report):
    """Applies rule R38 by restricting sudo usage through a dedicated group with exclusive execute permissions on the sudo binary."""

    reference_data = {
        "description": "Restrict sudo usage by creating a dedicated group with exclusive execute permissions on the sudo binary.",
        "expected": {
            "permissions": "4750",
            "owner": "root",
            "group": "sudogrp",
        },
    }

    r38_data = report.get("access_management", {}).get("R38", {})

    if not r38_data.get("apply", False):
        print("- R38: No action required.")
        return "Compliant"

    print("\n    Applying rule R38 (Restrict sudo usage)    \n")

    # Check for detected elements in the report
    detected_elements = r38_data.get("detected_elements", {})

    if not detected_elements:
        print("Rule R38: No elements detected for sudo usage restriction.")
        return "Failed"

    permissions = detected_elements.get("permissions", "")
    owner = detected_elements.get("owner", "")
    group = detected_elements.get("group", "")

    print(f"🔹 Current permissions: {permissions}, Owner: {owner}, Group: {group}")

    # Backup the sudo file before any modification
    print("🔹 Creating a backup of /usr/bin/sudo...")
    serveur.exec_command("sudo rm -f /usr/bin/sudo.back_R38")  # Remove the old backup if it exists
    serveur.exec_command("sudo cp /usr/bin/sudo /usr/bin/sudo.back_R38")

    # Check if the sudogrp group exists
    _, stdout, stderr = serveur.exec_command("getent group sudogrp")
    group_output = stdout.read().decode().strip()
    if not group_output:
        print("🔹 The 'sudogrp' group does not exist. Creating the group...")
        serveur.exec_command("sudo groupadd sudogrp")

    # Ask the user for additional users (comma-separated)
    additional_users_input = input("Enter additional users to add to the 'sudogrp' group, separated by commas (or press Enter to skip): ")
    additional_users = [user.strip() for user in additional_users_input.split(",")] if additional_users_input else []

    # Add root and the specified users to the sudogrp group
    users_to_add = ["root"] + additional_users
    for user in users_to_add:
        print(f"🔹 Adding user '{user}' to the 'sudogrp' group...")

        # Add the user to the sudogrp group
        _, stdout, stderr = serveur.exec_command(f"sudo usermod -aG {reference_data['expected']['group']} {user}")
        error_message = stderr.read().decode().strip()

        if error_message:
            print(f"❌ Error adding user '{user}' to the 'sudogrp' group: {error_message}")
        else:
            print(f"✅ User '{user}' added to the 'sudogrp' group.")
    #Changer group
    if group != reference_data["expected"]["group"]:
        print(f"🔹 Changing the group of /usr/bin/sudo to {reference_data['expected']['group']}.")
        _, stdout, stderr=serveur.exec_command(f"sudo chown :{reference_data['expected']['group']} /usr/bin/sudo")
        if error_message:
            print(f"❌ Erreur lors de la modification du groupe de /usr/bin/sudo : {error_message}")
        else:
            print(f"✅ Groupe de /usr/bin/sudo modifié avec succès.")

    # If the permissions, owner, or group are not compliant, modify them
    if permissions != reference_data["expected"]["permissions"]:
        print(f"🔹 Changing the permissions of /usr/bin/sudo to {reference_data['expected']['permissions']}.")
        serveur.exec_command(f"sudo chmod {reference_data['expected']['permissions']} /usr/bin/sudo")

    if owner != reference_data["expected"]["owner"]:
        print(f"🔹 Changing the owner of /usr/bin/sudo to {reference_data['expected']['owner']}.")
        serveur.exec_command(f"sudo chown {reference_data['expected']['owner']} /usr/bin/sudo")
    
    # Update the report
    update_report('renforce', 'access_management', 'R38')    
    print("✅ R38 successfully applied.")
   
# Regle 41
def apply_R41(serveur, report):
    """Applique la règle R41 en ajoutant les directives NOEXEC au fichier sudoers pour restreindre certaines commandes."""

    # Définition des commandes restreintes avec NOEXEC
    expected_elements = [
        "Cmnd_Alias  NOEXEC_CMDS = /bin/vi, /usr/bin/vi, /bin/vim, /usr/bin/vim, /bin/nano, /usr/bin/nano, /bin/emacs, /usr/bin/emacs",
        "%sudo       ALL=(ALL:ALL) NOEXEC: NOEXEC_CMDS"
    ]

    r41_data = report.get("access_management", {}).get("R41", {})

    if not r41_data.get("apply", False):
        print("- R41: No action required.")
        return "Compliant"

    print("\n    Applying rule R41 (Restrict process execution with NOEXEC)    \n")

    detected_elements = r41_data.get("detected_elements", [])

    # Vérifier les éléments manquants
    missing_elements = expected_elements if not detected_elements else [
        line for line in expected_elements if line not in detected_elements
    ]

    if not missing_elements:
        print("✅ R41 is already correctly applied.")
        return "Compliant"

    print(f"🔹 Adding NOEXEC directives to /etc/sudoers: {missing_elements}")

    # Sauvegarde du fichier sudoers avant modification
    print("🔹 Creating a backup of /etc/sudoers...")
    serveur.exec_command("sudo cp /etc/sudoers /etc/sudoers.back_R41")

    # Copier sudoers vers un fichier temporaire
    temp_file = "/tmp/sudoers_modif_R41"
    serveur.exec_command(f"sudo cp /etc/sudoers {temp_file}")

    # Ajouter les directives manquantes au fichier temporaire
    directives_to_add = "\n".join(missing_elements)
    serveur.exec_command(f"echo '{directives_to_add}' | sudo tee -a {temp_file} > /dev/null")

    # Vérifier la syntaxe du fichier temporaire avant de l'appliquer
    _, stdout, stderr = serveur.exec_command(f"sudo visudo -c -f {temp_file}")
    error_message = stderr.read().decode().strip()

    if error_message:
        print(f"❌ Syntax error in modified sudoers file: {error_message}")
        print("🚨 The original sudoers file remains unchanged.")
        print(f"🔹 Removing temporary file: {temp_file}")
        serveur.exec_command(f"sudo rm -f {temp_file}")
        return "Failed"

    # Appliquer la configuration validée
    serveur.exec_command(f"sudo cp {temp_file} /etc/sudoers")
    # Update the report
    update_report('renforce', 'access_management', 'R41')  
    print("✅ R41 applied successfully.")

    # Suppression du fichier temporaire après succès
    serveur.exec_command(f"sudo rm -f {temp_file}")
    

#Regle 57
def apply_R57(serveur, report):
    """Applique la règle R57 pour limiter les exécutables avec setuid/setgid root aux stricts nécessaires."""

    r57_data = report.get("access_management", {}).get("R57", {})

    if not r57_data.get("apply", False):
        print("- R57: No action required.")
        return "Compliant"

    print("\n    Applying rule R57 (Restrict setuid/setgid executables)    \n")

    unauthorized_files = r57_data.get("unauthorized_elements", [])

    if not unauthorized_files:
        print("✅ R57: No unauthorized setuid/setgid files found.")
        return "Compliant"

    file_count = len(unauthorized_files)

    print(f"🔍 Found {file_count} unauthorized setuid/setgid files:")

    # Affichage des fichiers
    if file_count <= 20:
        for file in unauthorized_files:
            print(f"   - {file}")
    else:
        for file in unauthorized_files[:20]:  # Affiche les 20 premiers
            print(f"   - {file}")
        
        # Sauvegarde des fichiers détectés dans un fichier temporaire sur le serveur
        temp_file = "/tmp/unauthorized_setuid_files"
        file_list = "\n".join(unauthorized_files)
        serveur.exec_command(f"echo '{file_list}' | sudo tee {temp_file} > /dev/null")

    print("\n📌 To manually check all setuid/setgid files, run:")
    print(f"   🔹 find / -perm -4000 -o -perm -2000 2>/dev/null\n")
    input("\nPress Enter to continue...")

    # Commande de révocation des permissions setuid/setgid
    revoke_cmd = " ".join(f"sudo chmod u-s,g-s {file}" for file in unauthorized_files)
   
    # Demande de confirmation utilisateur
    choice = input("❓ Do you want to revoke these permissions? (y=yes / n=no): ").strip().lower()
    if choice == "y":
        print("🔹 Revoking setuid/setgid permissions from unauthorized files...")
        serveur.exec_command(revoke_cmd)
        # Update the report
        update_report('renforce', 'access_management', 'R57')  
        print("✅ Rule 57 : Setuid/setgid permissions revoked.")       
    else:
        print("⚠️ No changes made. Manual review required.")
        return "Review Required"

#Regle 64
def apply_R64(serveur, report):
    """Applique la règle R64 pour restreindre les services et exécutables aux privilèges minimaux requis."""

    r64_data = report.get("access_management", {}).get("R64", {})

    if not r64_data.get("apply", False):
        print("- R64: No action required.")
        return "Compliant"

    print("\n    Applying rule R64 (Restrict services and executables to minimal privileges)    \n")

    unauthorized_files = r64_data.get("unauthorized_elements", [])

    if not unauthorized_files:
        print("✅ R64: All services and executables use minimal required privileges.")
        return "Compliant"

    file_count = len(unauthorized_files)

    print(f"🔍 Found {file_count} services/executables with excessive privileges:")

    # Affichage des fichiers
    if file_count <= 20:
        for file in unauthorized_files:
            print(f"   - {file}")
    else:
        for file in unauthorized_files[:20]:  # Affiche les 20 premiers
            print(f"   - {file}")
        print("\n⚠️ Too many files to display! Run the following command to see them all:")
        print("   🔹 cat /tmp/unauthorized_privilege_files\n")

        # Sauvegarde des fichiers détectés dans un fichier temporaire sur le serveur
        temp_file = "/tmp/unauthorized_privilege_files"
        file_list = "\n".join(unauthorized_files)
        serveur.exec_command(f"echo '{file_list}' | sudo tee {temp_file} > /dev/null")

    print("\n📌 To manually check all files with excessive privileges, run:")
    print(f"   🔹 ps -eo euser,egroup,uid,gid,comm\n")
    input("\nPress Enter to continue...")

    # Commande de restriction des privilèges excessifs
    restrict_cmd = " ".join(f"sudo chmod o-rwx {file}" for file in unauthorized_files)
    # Demande de confirmation utilisateur
    choice = input("❓ Do you want to restrict privileges on these services/executables? (y=yes / n=no): ").strip().lower()
    if choice == "y":
        print("🔹 Restricting privileges on unauthorized services/executables...")
        serveur.exec_command(restrict_cmd)
        # Update the report
        update_report('renforce', 'access_management', 'R64')  
        print("✅ Rule 64 : Privileges restricted.")        
    else:
        print("⚠️ No changes made. Manual review required.")
        return "Review Required"

######################    Fin de gestion acess niveau renforcé    ##########################


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
            "R55": (apply_R55, "Isolate user temporary directories")            
        },
        "renforce": {
            "R29" : (apply_R29, "Restrict access to /boot directory"),
            "R38" : (apply_R38, "Restrict sudo to a dedicated group"),
            "R41" : (apply_R41, "Check sudo directives using NOEXEC"),
            "R57" : (apply_R57, "Avoid executables with setuid root and setgid root"),
            "R64" : (apply_R64, "Configure services with minimal privileges")
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, None): 
                print(f"-> Applying rule {rule_id}: {comment}")
                function(serveur, apply_data)

    print(f"\n- Corrections applied - ACCESS MANAGEMENT - Level {niveau.upper()}")
