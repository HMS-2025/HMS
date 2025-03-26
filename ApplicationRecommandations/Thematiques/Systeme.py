import yaml

#=========== Global ==========
application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"

def execute_ssh_command(client, command):
    """Execute an SSH command and return output and error."""
    stdin, stdout, stderr = client.exec_command(command)
    output = list(filter(None, stdout.read().decode().strip().split("\n")))
    error = stderr.read().decode().strip()
    return output, error

def update(application_file, analyse_file, thematique, rule):
    with open(application_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Compliant'
    with open(application_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

    with open(analyse_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = True
    data[thematique][rule]['status'] = 'Compliant'
    with open(analyse_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def update_report(level, thematique, rule):
    if level == 'moyen':
        update(application_moyen, analyse_moyen, thematique, rule)

def apply_r8(client, report):
    r8_data = report.get("R8", {})
    if not r8_data.get("apply", False):
        print("- R8: No action required.")
        return "Compliant"

    print("- Applying memory security options at boot")
    grub_files = ["/etc/default/grub.d/50-cloudimg-settings.cfg"]
    grub_file = None

    # Locate the GRUB configuration file
    for file in grub_files:
        output, _ = execute_ssh_command(client, f"test -f {file} && echo 'FOUND' || echo 'MISSING'")
        if output and output[0] == "FOUND":
            grub_file = file
            break

    if not grub_file:
        print("Error: GRUB configuration file not found.")
        return "Non-Compliant"

    # Backup the existing GRUB file
    grub_backup = f"{grub_file}.backup"
    execute_ssh_command(client, f"sudo cp -n {grub_file} {grub_backup}")
    print(f"Backup created: {grub_backup}")

    # Read expected elements and apply them
    detected_elements = r8_data.get("detected_elements", [])
    expected_elements = r8_data.get("expected_elements", [])
    if not expected_elements:
        print("Error: No expected elements defined for R8.")
        return "Non-Compliant"

    for param in expected_elements:
        key, value = param.split("=", 1)
        if key in detected_elements:
            # Update existing parameter value
            execute_ssh_command(client, f"sudo sed -i 's|{key}=[^ ]*|{key}={value}|g' {grub_file}")
        else:
            # Add missing parameter if not already present
            execute_ssh_command(client, f"sudo grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' {grub_file} || echo 'GRUB_CMDLINE_LINUX_DEFAULT=\"\"' | sudo tee -a {grub_file} > /dev/null")
            execute_ssh_command(client, f"sudo sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/s|\"$| {key}={value}\"|' {grub_file}")
    # Update GRUB settings
    execute_ssh_command(client, "sudo update-grub")
    print("GRUB configuration updated successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R8')
    print("Report updated for R8.")

def apply_r9(client, report):
    
    # Define the reference expected kernel settings
    expected_elements = {
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "2",
        "kernel.pid_max": "65536",
        "kernel.perf_cpu_time_max_percent": "1",
        "kernel.perf_event_max_sample_rate": "1",
        "kernel.perf_event_paranoid": "2",
        "kernel.randomize_va_space": "2",
        "kernel.sysrq": "0",
        "kernel.unprivileged_bpf_disabled": "1",
        "kernel.panic_on_oops": "1"
    }

    r9_data = report.get("R9", {})
    if not r9_data.get("apply", False):
        print("- R9: No action required.")
        return "Compliant"

    print("- Applying kernel security settings")
    sysctl_file = "/etc/sysctl.conf"
    backup_file = f"{sysctl_file}.backup"

    # Create a backup of the sysctl file
    execute_ssh_command(client, f"sudo cp -n {sysctl_file} {backup_file}")
    print(f"Backup created: {backup_file}")

    # Load detected values from the report
    detected_elements = r9_data.get("detected", {})

    # Apply each expected kernel parameter
    for kernel_param, expected_value in expected_elements.items():
        # Check if the parameter is detected and matches the expected value
        detected_value = detected_elements.get(kernel_param)
        if detected_value != expected_value:
            print(f"- Setting {kernel_param} to {expected_value} (detected: {detected_value})")
            execute_ssh_command(client, f"sudo sed -i '/^{kernel_param}/d' {sysctl_file}")  # Remove existing entry if present
            execute_ssh_command(client, f"echo '{kernel_param} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")

    # Reload the sysctl settings
    execute_ssh_command(client, "sudo sysctl -p")
    print("Kernel security settings applied successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R9')
    print("Report updated for R9.")

def apply_r11(client, report):
    # Define the reference expected setting for Yama LSM
    expected_elements = {
        "kernel.yama.ptrace_scope": "1"
    }

    r11_data = report.get("R11", {})
    if not r11_data.get("apply", False):
        print("- R11: No action required.")
        return "Compliant"

    print("- Applying Yama LSM settings")
    sysctl_file = "/etc/sysctl.conf"
    backup_file = f"{sysctl_file}.backup"

    # Create a backup of the sysctl file
    execute_ssh_command(client, f"sudo cp -n {sysctl_file} {backup_file}")
    print(f"Backup created: {backup_file}")

    # Load detected values from the report
    detected_elements = r11_data.get("detected", {})

    # Apply the Yama LSM parameter if needed
    for kernel_param, expected_value in expected_elements.items():
        detected_value = detected_elements.get(kernel_param)
        if detected_value != expected_value:
            print(f"- Setting {kernel_param} to {expected_value} (detected: {detected_value})")
            execute_ssh_command(client, f"sudo sed -i '/^{kernel_param}/d' {sysctl_file}")  # Remove existing entry if present
            execute_ssh_command(client, f"echo '{kernel_param} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")

    # Reload the sysctl settings
    execute_ssh_command(client, "sudo sysctl -p")
    print("Yama LSM setting applied successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R11')
    print("Report updated for R11.")

def apply_r14(client, report):
    # Define the reference expected filesystem security settings
    expected_elements = {
        "fs.suid_dumpable": "0",
        "fs.protected_fifos": "2",
        "fs.protected_regular": "2",
        "fs.protected_symlinks": "1",
        "fs.protected_hardlinks": "1"
    }

    r14_data = report.get("R14", {})
    if not r14_data.get("apply", False):
        print("- R14: No action required.")
        return "Compliant"

    print("- Applying filesystem security settings")
    sysctl_file = "/etc/sysctl.conf"
    backup_file = f"{sysctl_file}.backup"

    # Create a backup of the sysctl file
    execute_ssh_command(client, f"sudo cp -n {sysctl_file} {backup_file}")
    print(f"Backup created: {backup_file}")

    # Load detected values from the report
    detected_elements = r14_data.get("detected", {})

    # Apply each expected fs parameter
    for fs_param, expected_value in expected_elements.items():
        detected_value = detected_elements.get(fs_param)
        if detected_value != expected_value:
            print(f"- Setting {fs_param} to {expected_value} (detected: {detected_value})")
            execute_ssh_command(client, f"sudo sed -i '/^{fs_param}/d' {sysctl_file}")  # Remove existing entry if present
            execute_ssh_command(client, f"echo '{fs_param} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")

    # Reload the sysctl settings
    execute_ssh_command(client, "sudo sysctl -p")
    print("Filesystem security settings applied successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R14')
    print("Report updated for R14.")




#######################################################################################
#                                                                                     #
#                                   Niveau renforcé                                   #
#                                                                                     #
#######################################################################################

#Regle 36
def apply_R36(serveur, report):
    """
    Applies rule R36 by checking and allowing the user to select a valid umask value.
    The chosen umask will be persisted in /etc/profile by modifying a temporary copy.
    A backup of /etc/profile is created before making changes.
    """
    
    r36_data = report.get("system", {}).get("R36", {})

    if not r36_data.get("apply", False):
        print("- R36: No action required.")
        return "Compliant"

    print("\n    Applying rule R36 (Check umask in /etc/profile)    \n")

    detected_umask = r36_data.get("detected_elements", '')
    valid_umask_values = ['027', '077', '022']  # Accepted umask values

    print(f"🔍 Detected umask: {detected_umask}")

    if detected_umask in valid_umask_values:
        print("✅ umask is already correctly set.")
        return "Compliant"
    
    print(f"⚠️ The detected umask '{detected_umask}' is invalid.")
    print("\nChoose a valid umask value:")
    for idx, umask in enumerate(valid_umask_values, 1):
        print(f"{idx}. {umask}")

    try:
        choice = int(input("Please enter the number corresponding to the desired umask value: "))
        if choice < 1 or choice > len(valid_umask_values):
            print("❌ Invalid choice. No changes were made.")
            return "Failed"
        
        chosen_umask = valid_umask_values[choice - 1]
        print(f"🔹 Setting umask to '{chosen_umask}'...")

        # Créer une sauvegarde de /etc/profile
        print("🔹 Creating a backup of /etc/profile...")
        serveur.exec_command("sudo cp /etc/profile /etc/profile.back_R36")

        # Copier /etc/profile dans un fichier temporaire
        temp_file = "/tmp/profile_temp"
        serveur.exec_command(f"sudo cp /etc/profile {temp_file}")

        # Remplacer la ligne existante commençant par "umask" ou ajouter la ligne à la fin
        # La commande sed ci-dessous remplace la ligne si elle existe, sinon ajoute à la fin.
        modify_cmd = f"sudo sh -c \"grep -q '^umask' {temp_file} && sed -i 's/^umask .*/umask {chosen_umask}/' {temp_file} || echo 'umask {chosen_umask}' >> {temp_file}\""
        print(f"🔹 Executing: {modify_cmd}")
        _, stdout, stderr = serveur.exec_command(modify_cmd)
        sed_error = stderr.read().decode().strip()
        if sed_error:
            print(f"❌ Error modifying the temporary file: {sed_error}")
            serveur.exec_command(f"sudo rm -f {temp_file}")
            return "Failed"

        # Vérifier que le fichier temporaire contient la ligne "umask {chosen_umask}"
        _, stdout, stderr = serveur.exec_command(f"grep '^umask' {temp_file}")
        modified_line = stdout.read().decode().strip()
        if modified_line != f"umask {chosen_umask}":
            print(f"❌ umask verification failed in the temporary file. Expected: 'umask {chosen_umask}', Got: '{modified_line}'")
            print("🔹 Deleting the temporary file...")
            serveur.exec_command(f"sudo rm -f {temp_file}")
            return "Failed"

        print(f"✅ umask has been successfully set to '{chosen_umask}' in the temporary file.")

        # Remplacer /etc/profile par le fichier temporaire
        print("🔹 Replacing /etc/profile with the modified temporary file...")
        serveur.exec_command(f"sudo cp {temp_file} /etc/profile && source /etc/profile")
        serveur.exec_command("sudo source /etc/profile")

        # Supprimer le fichier temporaire
        print("🔹 Deleting the temporary file...")
        serveur.exec_command(f"sudo rm -f {temp_file}")
        
        # Update the report to reflect the changes
        update_report('renforce', 'system', 'R36')
        print("✅ Rule R36 applied successfully.")
          
    except ValueError:
        print("❌ Invalid input. Please enter a number corresponding to the umask value.")
        return "Failed"

#Regle 37
def apply_R37(serveur, report):
    """
    Applies rule R37: Ensure that at least one MAC mechanism (SELinux, AppArmor, SMACK, or Tomoyo)
    is active. If none is active, the user is prompted to choose a MAC mechanism to install.
    If activation fails, the package is uninstalled.
    """
    r37_data = report.get("system", {}).get("R37", {})

    if not r37_data.get("apply", False):
        print("- R37: No action required.")
        return "Compliant"

    print("\n    Applying rule R37 (Check that MAC is enabled)    \n")
    
    expected_message = ("At least one MAC mechanism (SELinux, AppArmor, SMACK, or Tomoyo) should be active.")
    print(f"🔍 Expected: {expected_message}")

    detected_elements = r37_data.get("detected_elements", [])
    print("🔍 Detected:")
    for element in detected_elements:
        print(f"   - {element}")

    # Check if any MAC mechanism is active (case-insensitive)
    mac_active = any("true" in element.lower() for element in detected_elements)
    
    if mac_active:
        print("✅ At least one MAC mechanism is active. Rule R37 is compliant.")
        return "Compliant"
    else:
        print("❌ No MAC mechanism is active.")
        print("\nYou can install one of the following MAC mechanisms:")
        print("1. AppArmor")
        print("2. SELinux")
        print("3. SMACK")
        print("4. Tomoyo, required kernel permission, so only valide the physical host not for container")
        
        choice = input("Please enter the number corresponding to the MAC mechanism you want to install: ").strip()
        
        try:
            choice = int(choice)
        except ValueError:
            print("❌ Invalid input. No changes made.")
            return "Failed"
        
        uninstall_cmd = None
        if choice == 1:
            print("🔹 Installing AppArmor...")
            install_cmd = "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils"
            activate_cmd = "sudo systemctl enable apparmor && sudo systemctl start apparmor"
            uninstall_cmd = "sudo apt-get remove -y apparmor apparmor-utils"
        elif choice == 2:
            print("🔹 Installing SELinux...")
            install_cmd = "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y selinux-basics selinux-policy-default"
            activate_cmd = "sudo selinux-activate"  # Exemple, à adapter selon la distro.
            uninstall_cmd = "sudo apt-get remove -y selinux-basics selinux-policy-default"
        elif choice == 3:
            print("🔹 Installing SMACK...")
            print("⚠️ Automatic installation for SMACK is not supported. Please install it manually.")
            return "Review Required"
        elif choice == 4:
            print("🔹 Installing Tomoyo...")
            install_cmd = "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tomoyo-tools"
            activate_cmd = "sudo modprobe tomoyo && sudo tomoyo-init && sudo grubby --update-kernel=ALL --args='security=tomoyo'"
            uninstall_cmd = "sudo apt-get remove -y tomoyo-tools"
        else:
            print("❌ Invalid choice. No changes made.")
            return "Failed"
        
        # Execute the installation command.
        _, stdout, stderr = serveur.exec_command(install_cmd)
        install_output = stdout.read().decode().strip()
        install_error = stderr.read().decode().strip()
        if install_error:
            print(f"❌ Error installing the chosen MAC mechanism: {install_error}")
            return "Failed"
        print(f"✅ Installation output: {install_output}")
        
        # Activate the MAC mechanism.
        print("🔹 Activating the MAC mechanism...")
        _, stdout, stderr = serveur.exec_command(activate_cmd)
        activate_output = stdout.read().decode().strip()
        activate_error = stderr.read().decode().strip()
        if activate_error:
            print(f"❌ Error activating the chosen MAC mechanism: {activate_error}")
            if uninstall_cmd:
                print("🔹 Attempting to uninstall the package due to activation failure...")
                serveur.exec_command(uninstall_cmd)
                print("✅ Package uninstalled.")
            return "Failed"
        print(f"✅ Activation output: {activate_output}")

        # Update the report to reflect the changes
        update_report('renforce', 'system', 'R37')        
        print("✅ MAC mechanism installed and activated successfully.")
       
#Regle 45
#Ajout de profil en complain pour tester cette fonction
#echo -e "profile test_R45 /usr/bin/env {\n  # Allow read, inherit, and execute permissions\n  /usr/bin/env rix,\n}" | sudo tee /etc/apparmor.d/test_R45 > /dev/null && sudo apparmor_parser -r /etc/apparmor.d/test_R45

#Activation 
# sudo aa-complain /etc/apparmor.d/test_R45

#Deleting the profil after the test 
#sudo rm /etc/apparmor.d/test_R45 && sudo apparmor_parser -R /etc/apparmor.d/test_R45

def apply_R45(serveur, report):
    """
    Ensures all AppArmor profiles are in enforce mode.
    If all profiles are already in enforce mode (0 complain), no action is needed.
    """
    r45_data = report.get("system", {}).get("R45", {})

    if not r45_data.get("apply", False):
        print("- R45: No action required.")
        return "Compliant"

    if "0 complain" in r45_data.get("detected_elements"):
        print("All profils are in enforced mode, so your safe")
        return "Compliant"
        
    print("\n    Applying rule R45 (Ensure all AppArmor profiles are in enforce mode)    \n")

    # Vérifier si AppArmor est actif
    _, stdout, _ = serveur.exec_command("aa-status --json")
    aa_status = stdout.read().decode().strip()

    if "complain" not in aa_status and "enforce" not in aa_status:
        print("❌ AppArmor is not active on this system.")
        return "Failed"

    # Vérifier si des profils sont en mode "complain"
    _, stdout, _ = serveur.exec_command("aa-status | grep 'complain mode'")
    complain_profiles = stdout.read().decode().strip().split("\n")

    complain_count = len(complain_profiles) if complain_profiles[0] else 0

    # Afficher les profils en complain mode et demander confirmation
    print(f"🔍 Found {complain_count} profiles in complain mode.")
    print("\nProfiles in complain mode:")
    for profile in complain_profiles:
        print(f"  - {profile.strip()}")

    choice = input("\nDo you want to enforce all these profiles? (y/n): ").strip().lower()
    if choice != 'y':
        print("❌ User declined to enforce profiles. No changes made.")
        return "Failed"

    # Appliquer enforce sur chaque profil
    for profile in complain_profiles:
        profile_name = profile.split()[-1]  # Extraire le nom du profil
        print(f"🔹 Enforcing profile: {profile_name}...")
        _, _, stderr = serveur.exec_command(f"sudo aa-enforce {profile_name}")
        error_message = stderr.read().decode().strip()
        if error_message:
            print(f"❌ Failed to enforce {profile_name}: {error_message}")
    
    # Vérifier à nouveau le statut après l'application
    _, stdout, _ = serveur.exec_command("aa-status | grep 'complain mode'")
    remaining_complain = stdout.read().decode().strip()

    if remaining_complain:
        print("❌ Some profiles are still in complain mode.")
        return "Failed"
    
    # Update the report to reflect the changes
    update_report('renforce', 'system', 'R45')
    print("✅ All AppArmor profiles are now in enforce mode.")
    
###################### Fin par niveau renforcé   #######################




#=========== Main ==========
def apply_system(client, niveau, report_data):
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("system", None)
    if apply_data is None:
        return

    rules = {
        "moyen": {
            "R8": (apply_r8, "Configurer les options de sécurité mémoire au démarrage"),
            "R9": (apply_r9, "Configurer les paramètres de sécurité du noyau"),
            "R11": (apply_r11, "Activer et configurer Yama LSM"),
            "R14": (apply_r14, "Configurer la sécurité des systèmes de fichiers"),
        },

        "renforce": {
            "R36": (apply_R36, "Check umask in /etc/profile (accepted values: 027 or 077, default 022)"),
            "R37": (apply_R37, "Check that MAC is enabled (SELinux, AppArmor, SMACK, or Tomoyo)"),
            "R45": (apply_R45, "Ensure all AppArmor profiles are in enforce mode"),
               
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

    print(f"\n- Corrections applied - system - Level {niveau.upper()}")
