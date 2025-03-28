import yaml
#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"


def execute_ssh_command(serveur, command):
    """Executes an SSH command on the remote server and returns the output and errors."""
    stdin, stdout, stderr = serveur.exec_command(command)
    output = list(filter(None, stdout.read().decode().strip().split("\n")))
    error = stderr.read().decode().strip()
    return output, error

def update(application_file, analyse_file, thematique, rule):
    # Update in the application file
    with open(application_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Compliant'
    with open(application_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

    # Update in the analysis file
    with open(analyse_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = True
    data[thematique][rule]['status'] = 'Compliant'
    with open(analyse_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def update_report(level, thematique, rule):
    if level == 'min':
        update(application_min, analyse_min, thematique, rule)
    elif level == 'moyen':
        update(application_moyen, analyse_moyen, thematique, rule)


def ask_for_approval(rule, detected_elements):
    print(f"\n[!] Detected elements for rule {rule}:")
    for elem in detected_elements:
        print(f"- {elem}")
    return input(f"Apply rule {rule} for these elements? (y/n): ").strip().lower() == 'y'

def ask_for_element_approval(rule, elem):
    while True:
        response = input(f"Remove {elem} as part of rule {rule}? (y/n/q to quit the rule): ").strip().lower()
        if response in ['y', 'n', 'q']:
            return response
        print("Invalid response. Enter 'y' for yes, 'n' for no, or 'q' to quit.")

def apply_r58(client, report):
    r58_data = report.get("R58", {})
    if not r58_data.get("apply", False):
        print("- R58: No action required.")
        return "Compliant"
    
    expected_packages = r58_data.get("expected_elements", [])
    if not expected_packages:
        print("- No expected packages defined for rule R58.")
        return "Compliant"
    
    installed_packages = r58_data.get("detected_elements", [])
      
    detected_elements = [pkg for pkg in installed_packages if pkg and pkg not in expected_packages]

    if detected_elements and ask_for_approval("R58", detected_elements):
        for elem in detected_elements:
            response = ask_for_element_approval("R58", elem)
            if response == 'q':
                print("Stopping rule R58.")
                break
            elif response == 'y':
                print(f"- Removing {elem}...")
                _, err = execute_ssh_command(client, f"sudo apt-get remove --purge -y {elem}")
                if err:
                    print(f"Error while removing {elem} : {err}")
                else:
                    print(f"{elem} successfully removed.")
            else:
                print(f"{elem} kept.")
        update_report('min', 'maintenance', 'R58')

def apply_r59(client, report):
    r59_data = report.get("R59", {})
    if not r59_data.get("apply", False):
        print("- R59: No action required.")
        return "Compliant"

    detected_elements = r59_data.get("detected_elements", [])
    if not detected_elements:
        print("- No problematic repositories detected.")
        return "Compliant"

    if ask_for_approval("R59", detected_elements):
        sources_file = "/etc/apt/sources.list"
        for repo in detected_elements:
            response = ask_for_element_approval("R59", repo)
            if response == 'q':
                print("Stopping rule R59.")
                break
            elif response == 'y':
                print(f"- Removing repository {repo}...")
                _, err = execute_ssh_command(client, f"sudo sed -i '/{repo}/d' {sources_file}")
                if err:
                    print(f"Error while removing {repo} : {err}")
                else:
                    print(f"{repo} successfully removed.")
            else:
                print(f"{repo} kept.")
        update_report('min', 'maintenance', 'R59')


def apply_r5(client, report):
    try:
        # Charger la configuration SSH
        config = load_config_ssh("ssh.yaml")
        admin_user = config.get("username")  #Recuperation de admin
        
        r5_data = report.get("R5", {})
        if not r5_data.get("apply", False):
            print("- R5: No action required.")
            return "Compliant"

        response = input("Would you like to configure a secure GRUB password? (y/n): ").strip().lower()
        if response != 'y':
            print("No changes applied.")
            return

        # Demander un mot de passe sécurisé
        while True:
            grub_password = input(f"Enter the password for GRUB admin '{admin_user}': ").strip()
            if grub_password:
                break
            print("Error: Password cannot be empty!")

        print("\n WARNING: The GRUB password is crucial! Losing it may prevent access to GRUB.")
        print(f" Your GRUB password: {grub_password}")
        input("Remember this password. Press Enter to continue...")

        # Vérifier si grub-mkpasswd-pbkdf2 est installé
        check_command, err = execute_ssh_command(client, "which grub-mkpasswd-pbkdf2")
        if err or not check_command:
            user_response = input("'grub-mkpasswd-pbkdf2' is not installed. Install it now? (y/n): ").strip().lower()
            if user_response == 'y':
                _, install_error = execute_ssh_command(client, "sudo apt-get install -y grub-common")
                if install_error:
                    print(f"Error installing grub-common: {install_error}")
                    return
            else:
                print("Package not installed. Cannot configure GRUB password.")
                return

        # Générer le hash PBKDF2
        print("Generating PBKDF2 hash for GRUB...")
        hash_output, err = execute_ssh_command(client, f"echo -e '{grub_password}\n{grub_password}' | grub-mkpasswd-pbkdf2")
        if err or not hash_output:
            print(f"Error generating the hash: {err}")
            return

        # Extraire le hash
        hashed_pass = None
        for line in hash_output:
            if "grub.pbkdf2" in line:
                hashed_pass = line.strip()
                break
        
        if not hashed_pass:
            print("Error: Hash not found.")
            return

        # Vérifier et créer le fichier 40_custom si nécessaire
        execute_ssh_command(client, "sudo touch /etc/grub.d/40_custom")
        execute_ssh_command(client, "sudo chmod +x /etc/grub.d/40_custom")

        # Ajouter la configuration GRUB dans /etc/grub.d/40_custom (et non directement dans grub.cfg)
        execute_ssh_command(client, f"sudo bash -c \"echo 'set superusers=\\\"{admin_user}\\\"' >> /etc/grub.d/40_custom\"")
        execute_ssh_command(client, f"sudo bash -c \"echo 'password_pbkdf2 {admin_user} {hashed_pass}' >> /etc/grub.d/40_custom\"")

        # Mettre à jour GRUB (ce qui régénère /boot/grub/grub.cfg)
        execute_ssh_command(client, "sudo update-grub")

        print(f" GRUB password successfully configured for user '{admin_user}'.")
    
    except Exception as e:
        print(f" An unexpected error occurred: {str(e)}")
    
    update_report('moyen', 'maintenance', 'R5')


def apply_maintenance(client, niveau, report_data):
    
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("maintenance", None)
    if apply_data is None:
        return

    rules = {
        "min": {
            "R58": (apply_r58, "Supprimer les paquets non attendus"),
            "R59": (apply_r59, "Supprimer les dépôts externes non attendus")
        },
        "moyen": {
            "R5": (apply_r5, "Configurer un mot de passe GRUB sécurisé")
        }
    }


    apply_data = report_data.get("maintenance", {})
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

    print(f"\n- Corrections applied - MAINTENANCE - Level {niveau.upper()}")
