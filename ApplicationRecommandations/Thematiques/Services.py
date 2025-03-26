import yaml

#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"


application_renforce = "./GenerationRapport/RapportApplication/application_renforce.yml"
analyse_renforce = "./GenerationRapport/RapportAnalyse/analyse_renfore.yml"

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
    if level == 'min':
        update(application_min, analyse_min, thematique, rule)
    elif level == 'moyen':
        update(application_moyen, analyse_moyen, thematique, rule)
    elif level == 'renforce':
        update(application_renforce, analyse_renforce, thematique, rule)

# ============================
# RULES - MINIMAL
# ============================

def apply_r62(serveur, report):
    r62_data = report.get("R62", {})
    if not r62_data.get("apply", False):
        print("R62: No action required.")
        return "Compliant"

    prohibited_services = r62_data.get("detected_prohibited_elements", [])
    if not prohibited_services:
        print(" No prohibited services detected.")
        return "Compliant"

    print(" Applying rule R62: Disabling prohibited services...")

    for service in prohibited_services:
        print(f" Disabling {service} and its associated sockets")
        execute_ssh_command(serveur, f"sudo systemctl stop {service}")
        execute_ssh_command(serveur, f"sudo systemctl disable {service}")

        socket_name = service.replace(".service", ".socket")
        execute_ssh_command(serveur, f"sudo systemctl stop {socket_name}")
        execute_ssh_command(serveur, f"sudo systemctl disable {socket_name}")

    update_report('min', 'services', 'R62')

    print(" R62: Prohibited services disabled.")
    return "Applied"

# ============================
# RULES - MEDIUM
# ============================

def apply_r35(serveur, report):
    r35_data = report.get("R35", {})
    if not r35_data.get("apply", False):
        print("R35: No action required.")
        return "Compliant"

    detected_accounts = r35_data.get("detected_elements", [])
    if not detected_accounts:
        print(" No shared service accounts detected.")
        return "Compliant"

    print(" Applying rule R35: Enforcing exclusive service accounts...")
    print("The following accounts are used by multiple services:")
    for account in detected_accounts:
        user = account.split()[1]
        print(f"- {user}")

    print("\n⚠️ This rule's application is not yet supported.\n")

def apply_r63(serveur, report):
    r63_data = report.get("R63", {})
    if not r63_data.get("apply", False):
        print("R63: No action required.")
        return "Compliant"

    detected_features = r63_data.get("detected_elements", [])
    if not detected_features:
        print(" No unnecessary capabilities found.")
        return "Compliant"

    print(" Applying rule R63: Removing unnecessary capabilities...")
    print("Files with capabilities:")
    for line in detected_features:
        print(f"- {line}")

    print("\n⚠️ This rule's application is not yet supported.\n")
    return "Applied"

def apply_r74(serveur, report):
    r74_data = report.get("R74", {})
    if not r74_data.get("apply", False):
        print("R74: No action required.")
        return "Compliant"

    print(" Applying rule R74: Hardening the local mail service...")

    expected = r74_data.get("expected_elements", {}).get("hardened_mail_service", {})

    for interface in expected.get("listen_interfaces", []):
        execute_ssh_command(serveur, f"sudo postconf -e 'inet_interfaces = {interface}'")

    # Ask user for domains to add to mydestination
    user_input = input("Enter domains to allow for local delivery (comma separated): ")
    domaines = [d.strip() for d in user_input.split(",") if d.strip()]

    if domaines:
        domain_list = ", ".join(domaines)
        execute_ssh_command(serveur, f"sudo postconf -e 'mydestination = {domain_list}'")
        print(f"Domains added to mydestination: {domain_list}")
    else:
        print("No domains added to mydestination.")

    execute_ssh_command(serveur, "sudo systemctl restart postfix")
    update_report('moyen', 'services', 'R74')

    print(" R74: Local mail service hardened.")
    return "Applied"

def apply_r75(serveur, report):
    r75_data = report.get("R75", {})
    if not r75_data.get("apply", False):
        print("R75: No action required.")
        return "Compliant"

    print(" Applying rule R75: Configuring mail aliases for service accounts...")

    expected_aliases = r75_data.get("expected_elements", [])

    print("Found aliases:")
    for alias in expected_aliases:
        print(f"- {alias}")

    print("\n⚠️ This rule's application is not yet supported.\n")



#######################################################################################
#                                                                                     #
#                          service niveau renforcé                                    #
#                                                                                     #
#######################################################################################
def apply_R10(serveur, report):
    """
    Applies rule R10 by ensuring that the kernel modules loading is set according to the expected value.
    If the detected value differs from the expected value, the script will update the configuration to match the expected value.
    A backup of the configuration file is created before making changes.
    """
    
    r10_data = report.get("services", {}).get("R10", {})

    if not r10_data.get("apply", False):
        print("- R10: No action required.")
        return "Compliant"

    print("\n    Applying rule R10 (Disable kernel modules loading)    \n")

    detected_elements = r10_data.get("detected_elements", '')
    expected_elements = r10_data.get("expected_elements", '1')

    if detected_elements == expected_elements:
        print("✅ Kernel modules loading is already set as expected.")
        return "Compliant"

    print(f"⚠️ Detected kernel modules loading is '{detected_elements}', expected: '{expected_elements}'")

    try:
        # Créer une sauvegarde du fichier de configuration actuel
        print("🔹 Creating a backup of the configuration file...")
        serveur.exec_command("sudo cp /etc/modprobe.d/blacklist.conf /etc/modprobe.d/blacklist.conf.back_R10")

        # Copier le fichier de configuration actuel dans un fichier temporaire
        temp_file = "/tmp/blacklist_temp.conf"
        serveur.exec_command(f"sudo cp /etc/modprobe.d/blacklist.conf {temp_file}")

        # Si la valeur détectée est différente de la valeur attendue, on met à jour la configuration
        if detected_elements != expected_elements:
            print(f"⚙️ Modifying kernel module loading configuration to '{expected_elements}'...")

            # Modifier le fichier temporaire pour correspondre à la valeur attendue
            modify_cmd = f"sudo sh -c \"echo 'kernel modules loading: {expected_elements}' >> {temp_file}\""
            print(f"🔹 Executing: {modify_cmd}")
            _, stdout, stderr = serveur.exec_command(modify_cmd)
            sed_error = stderr.read().decode().strip()
            if sed_error:
                print(f"❌ Error modifying the temporary file: {sed_error}")
                serveur.exec_command(f"sudo rm -f {temp_file}")
                return "Failed"

            # Vérification que le fichier temporaire a bien été mis à jour avec la valeur attendue
            _, stdout, stderr = serveur.exec_command(f"grep 'kernel modules loading: {expected_elements}' {temp_file}")
            modified_line = stdout.read().decode().strip()
            if modified_line != f"kernel modules loading: {expected_elements}":
                print(f"❌ Configuration verification failed. Expected: 'kernel modules loading: {expected_elements}', Got: '{modified_line}'")
                print("🔹 Deleting the temporary file...")
                serveur.exec_command(f"sudo rm -f {temp_file}")
                return "Failed"

            print(f"✅ Kernel module loading configuration has been updated to '{expected_elements}'.")

        # Remplacer le fichier de configuration par le fichier temporaire modifié
        print("🔹 Replacing the original configuration with the modified temporary file...")
        serveur.exec_command(f"sudo cp {temp_file} /etc/modprobe.d/blacklist.conf")

        # Supprimer le fichier temporaire
        print("🔹 Deleting the temporary file...")
        serveur.exec_command(f"sudo rm -f {temp_file}")

        #update report
        update_report('renforce', 'services', 'R10')
        print("✅ Rule R10 applied successfully.")
        

    except Exception as e:
        print(f"❌ An unexpected error occurred: {str(e)}")
        return "Failed"

#Regle 65
def apply_R65(serveur, report):
    """
    Applies rule R65 by checking the confinement of certain services.
    Since no expected elements are defined, it checks for the presence of specific services
    and provides a report. If there are more than 20 services, it only shows the commands 
    for confining or deconfing services for manual execution.
    """    
    r65_data = report.get("services", {}).get("R65", {})
    
    if not r65_data.get("apply", False):
        print("- R65: No action required.")
        return "Compliant"

    print("\n    Applying rule R65 (Check service confinement)    \n")
    
    detected_services = r65_data.get("detected_elements", [])
    
    if not detected_services:
        print("⚠️ No detected services found.")
        return "Failed"

    # Si plus de 20 services sont détectés, on affiche seulement les commandes pour confiner/déconfiner
    if len(detected_services) > 20:
        print(f"⚠️ More than 20 services detected. Displaying confinement/deconfing commands for manual execution:\n")
        print(f"To confine a service with AppArmor:  sudo aa-enforce <service_name>")
        print(f"To deconfine a service with AppArmor: sudo aa-complain <service_name>")
        input("\nPress Enter to continue...")
        return "Success"

    # Vérification du confinement des services
    confinement_status = {}
    
    for service in detected_services:
        # Vérifier si le service est confiné par AppArmor
        apparmor_check_cmd = f"sudo aa-status | grep '{service}'"
        _, stdout, stderr = serveur.exec_command(apparmor_check_cmd)
        
        if stdout.read().decode().strip():
            confinement_status[service] = "Confiné"
        else:
            confinement_status[service] = "Non confiné"
    
    print("\n🔒 Service confinement status:")
    for service, status in confinement_status.items():
        print(f"  - {service}: {status}")

    # Proposer de confiner ou déconfiner chaque service individuellement en fonction de son état
    for service in detected_services:
        current_status = confinement_status[service]
        print(f"\n🔧 Service : {service} \t Status: {current_status}")    
       
        if current_status == "Confiné":
            print("  - Action: You can deconfine this service.")
            action = input("  Type 'd' to deconfine, or 's' to skip: ").strip().lower()
            if action == 'd':
                print(f"Deconfining the service '{service}' with AppArmor...")
                deconfine_cmd = f"sudo aa-complain {service}"
                serveur.exec_command(deconfine_cmd)
                print(f"Service '{service}' is now deconfined.")
            elif action == 's':
                print(f"Skipping the service '{service}'.")
            else:
                print("Invalid input. Skipping this service.")
        
        elif current_status == "Non confiné":
            print("  - Action: You can confine this service.")
            action = input("  Type 'c' to confine, or 's' to skip: ").strip().lower()
            if action == 'c':
                print(f"Confining the service '{service}' with AppArmor...")
                confine_cmd = f"sudo aa-enforce {service}"
                serveur.exec_command(confine_cmd)
                print(f"Service '{service}' is now confined.")
            elif action == 's':
                print(f"Skipping the service '{service}'.")
            else:
                print("Invalid input. Skipping this service.")

    #update report
    update_report('renforce', 'services', 'R65')
    print("✅ Rule R65 applied successfully. Confinement check completed.")
    
    # Attendre que l'utilisateur appuie sur Entrée pour continuer
    input("\nPress Enter to continue...")
  

########################## Partie  serice ############################################



# ============================
# MAIN
# ============================

<<<<<<< HEAD
def apply_services(client, niveau, report_data):
=======
def apply_services(client, niveau , report_data):
>>>>>>> main
    fix_results = {}
    apply_data = report_data.get("services", None)
    if apply_data is None:
        return

    rules = {
        "min": {
            "R62": (apply_r62, "Disable prohibited services detected")
        },
        "moyen": {
            "R35": (apply_r35, "Use unique and exclusive service accounts"),
            "R63": (apply_r63, "Disable non-essential capabilities"),
            "R74": (apply_r74, "Harden the local mail service"),
            "R75": (apply_r75, "Configure mail aliases for service accounts")
        },
        "renforce": {
            "R10": (apply_R10, "Disable kernel modules loading"),
            "R65": (apply_R65, "Check service confinement"),
            
        }
    }

    apply_data = report_data.get("services", {})
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

<<<<<<< HEAD
    print(f"\n Fixes applied - SERVICES - niveau {level.upper()}")
=======
    print(f"\n Fixes applied - SERVICES - Level {niveau.upper()}")
>>>>>>> main
    return fix_results
