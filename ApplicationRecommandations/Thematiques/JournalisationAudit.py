import yaml,os

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


#######################################################################################
#                                                                                     #
#                        Journalisation niveau renforcé                               #
#                                                                                     #
#######################################################################################

#Regle 71
def apply_R71(serveur, report):
    """
    Applies rule R71 by ensuring secure and complete logging configuration, with backup, temporary file handling,
    and validation before applying the changes.
    """
    
    r71_data = report.get("logging", {}).get("R71", {})
    
    if not r71_data.get("apply", False):
        print("- R71: No action required.")
        return "Compliant"
    
    print("\n    Applying rule R71 (Ensure secure and complete logging configuration)    \n")
    
    expected_elements = r71_data.get("expected_elements", {})
    
    # Créer une sauvegarde de rsyslog.conf avant toute modification
    print("🔹 Creating a backup of /etc/rsyslog.conf...")
    serveur.exec_command("sudo cp /etc/rsyslog.conf /etc/rsyslog.conf.back_R71")
    
    # Créer un fichier temporaire pour les modifications
    temp_file = "/tmp/rsyslog_temp"
    print("🔹 Creating a temporary file for modifications...")
    serveur.exec_command(f"sudo cp /etc/rsyslog.conf {temp_file}")
    
    # Appliquer les configurations des logs d'authentification
    auth_logs = expected_elements.get("auth_logs_configured", [])
    for log_config in auth_logs:
        print(f"🔹 Adding or updating {log_config} to temporary rsyslog file...")
        modify_cmd = f"echo '{log_config}' | sudo tee -a {temp_file} > /dev/null"
        serveur.exec_command(modify_cmd)
    
    # Appliquer les événements système
    sys_events = expected_elements.get("sys_events_configured", [])
    for event_config in sys_events:
        print(f"🔹 Adding or updating {event_config} to temporary rsyslog file...")
        modify_cmd = f"echo '{event_config}' | sudo tee -a {temp_file} > /dev/null"
        serveur.exec_command(modify_cmd)
    
    # Appliquer les permissions des fichiers journaux
    log_files_permissions = expected_elements.get("log_files_permissions", {})
    for log_file, permissions in log_files_permissions.items():
        # Utiliser directement la valeur de permissions qui est une chaîne
        print(f"🔹 Setting permissions for {log_file} to {permissions}...")
        modify_cmd = f"sudo chmod {permissions} {log_file} && sudo chown root:adm {log_file}"
        serveur.exec_command(modify_cmd)
    
    # Configurer l'envoi sécurisé des journaux
    if expected_elements.get("log_forwarding_secure") == "TLS Enabled":
        print("🔹 Configuring secure log forwarding with TLS...")
        tls_config = "module(load=\"imtcp\")\ninput(type=\"imtcp\" port=\"514\")\n"
        modify_cmd = f"echo '{tls_config}' | sudo tee -a {temp_file} > /dev/null"
        serveur.exec_command(modify_cmd)
    
    # Vérifier que le fichier temporaire contient toutes les modifications attendues
    print("🔹 Verifying temporary rsyslog file for changes...")
    _, stdout, stderr = serveur.exec_command(f"grep 'auth' {temp_file}")
    if not stdout.read():
        print("❌ Auth logs configurations missing in temporary file.")
        serveur.exec_command(f"sudo rm -f {temp_file}")
        return "Failed"

    _, stdout, stderr = serveur.exec_command(f"grep 'syslog' {temp_file}")
    if not stdout.read():
        print("❌ Syslog events configurations missing in temporary file.")
        serveur.exec_command(f"sudo rm -f {temp_file}")
        return "Failed"

    print(f"✅ Temporary file verified. All expected configurations found.")
    
    # Remplacer rsyslog.conf par le fichier temporaire
    print("🔹 Replacing /etc/rsyslog.conf with the modified temporary file...")
    serveur.exec_command(f"sudo cp {temp_file} /etc/rsyslog.conf")
    
    # Redémarrer rsyslog pour appliquer les modifications
    print("🔹 Restarting rsyslog service to apply changes...")
    serveur.exec_command("sudo systemctl restart rsyslog")
    
    # Supprimer le fichier temporaire
    print("🔹 Deleting the temporary file...")
    serveur.exec_command(f"sudo rm -f {temp_file}")
    
    #update report
    update_report('renforce', 'logging', 'R71')
    print("✅ Rule R71 applied successfully.")
   

#Regle 72
def apply_R72(serveur, report):
    """
    Applies rule R72 by ensuring correct ownership and permissions of log files.
    Creates a backup of log files before modification, uses a temporary file for validation.
    """
    
    r72_data = report.get("logging", {}).get("R72", {})
    
    if not r72_data.get("apply", False):
        print("- R72: No action required.")
        return "Compliant"
    
    print("\n    Applying rule R72 (Ensure service log protection)    \n")
    
    expected_elements = r72_data.get("expected_elements", {})
    detected_elements = r72_data.get("detected_elements", {})
    
    for log_file, expected_values in expected_elements.items():
        expected_owner = expected_values.get("owner")
        expected_group = expected_values.get("group")
        expected_perms = expected_values.get("permissions")
        
        detected_values = detected_elements.get(log_file, {})
        detected_owner = detected_values.get("owner", "Not Found")
        detected_group = detected_values.get("group", "Not Found")
        detected_perms = detected_values.get("permissions", "Not Found")
        
        if detected_owner == expected_owner and detected_group == expected_group and detected_perms == expected_perms:
            print(f"✅ {log_file} is already correctly configured.")
            continue
        
        print(f"⚠️ Fixing {log_file} (Detected: owner={detected_owner}, group={detected_group}, permissions={detected_perms})")
        
        # Backup the original log file
        backup_file = f"{log_file}.back_R72"
        print(f"🔹 Creating backup: {backup_file}")
        serveur.exec_command(f"sudo cp {log_file} {backup_file}")
        
        # Create a temporary file for modifications
        temp_file = f"/tmp/{log_file.split('/')[-1]}_temp"
        serveur.exec_command(f"sudo cp {log_file} {temp_file}")
        
        if detected_owner != expected_owner:
            print(f"🔹 Setting owner: {expected_owner}")
            serveur.exec_command(f"sudo chown {expected_owner} {temp_file}")
        
        if detected_group != expected_group:
            print(f"🔹 Setting group: {expected_group}")
            serveur.exec_command(f"sudo chgrp {expected_group} {temp_file}")
        
        if detected_perms != expected_perms:
            print(f"🔹 Setting permissions: {expected_perms}")
            serveur.exec_command(f"sudo chmod {expected_perms} {temp_file}")
        
        # Validate changes
        _, stdout, stderr = serveur.exec_command(f"ls -l {temp_file}")
        validation_output = stdout.read().decode().strip()
        print(f"🔹 Validation result: {validation_output}")
        
        # Replace original file with validated temporary file
        print(f"🔹 Replacing {log_file} with the modified temporary file...")
        serveur.exec_command(f"sudo mv {temp_file} {log_file}")
        
        print(f"✅ {log_file} successfully updated.")
    
    #update report
    update_report('renforce', 'logging', 'R72')
    print("✅ Rule R72 applied successfully.")
    

#Fonction à test sur hote réel
#Regle 73
from datetime import datetime

def apply_R73(serveur, report):
    """
    Applique la règle R73 pour assurer que auditd est correctement configuré pour la journalisation de l'activité système,
    avec des sauvegardes, la gestion des répertoires temporaires et une validation finale.
    """

    r73_data = report.get("logging", {}).get("R73", {})
    
    if not r73_data.get("apply", False):
        print("- R73: No action required.")
        return "Compliant"
    
    print("\n    Applying rule R73 (Ensure auditd is configured properly for system activity logging)    \n")

    # 1. Backup des fichiers importants avant toute modification
    backup_dir = "/tmp/auditd_backup"
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"audit.rules.{timestamp}.bak")
    print(f"🔹 Creating backup of current audit rules at {backup_file}")
    # Utilisation de `cp` pour faire la sauvegarde
    serveur.exec_command(f"sudo cp /etc/audit/rules.d/audit.rules {backup_file}")
    
    # 2. Vérifier les permissions des répertoires temporaires
    tmp_dir = "/tmp"
    if os.path.exists(tmp_dir):
        print(f"🔹 Checking permissions for temporary directory: {tmp_dir}")
        # S'assurer que /tmp est sécurisé (permissions correctes)
        serveur.exec_command(f"sudo chmod 1777 {tmp_dir}")
    else:
        print(f"❌ Temporary directory {tmp_dir} does not exist.")
        return "Failed"

    # 3. Vérification si auditd est actif
    auditd_status = r73_data.get("detected_elements", {}).get("auditd_active", False)
    
    if not auditd_status:
        print("🔹 auditd is not active. Activating auditd...")
        # Activer et démarrer auditd
        serveur.exec_command("sudo systemctl enable auditd")
        serveur.exec_command("sudo systemctl start auditd")
    else:
        print("🔹 auditd is already active.")
    
    # 4. Vérification des règles d'audit existantes
    current_rules = r73_data.get("detected_elements", {}).get("rules", None)
    
    if current_rules is None:
        print("🔹 No auditd rules detected. Applying recommended rules...")
        # Ajouter les règles d'audit recommandées
        audit_rules = [
            "-w /sbin/insmod -p x",
            "-w /sbin/modprobe -p x",
            "-w /sbin/rmmod -p x",
            "-w /bin/kmod -p x",
            "-w /etc/ -p wa",
            "-a exit,always -S mount -S umount2",
            "-a exit,always -S ioperm -S modify_ldt",
            "-a exit,always -S get_kernel_syms -S ptrace",
            "-a exit,always -S prctl",
            "-a exit,always -F arch=b64 -S unlink -S rmdir -S rename",
            "-a exit,always -F arch=b64 -S creat -S open -S openat -F exit=-EACCES",
            "-a exit,always -F arch=b64 -S truncate -S ftruncate -F exit=-EACCES",
            "-a exit,always -F arch=b64 -S init_module -S delete_module",
            "-a exit,always -F arch=b64 -S finit_module",
            "-e 2"
        ]
        
        # Ajouter ces règles dans le fichier audit.rules
        audit_rules_file = "/etc/audit/rules.d/audit.rules"
        for rule in audit_rules:
            print(f"🔹 Adding rule: {rule}")
            modify_cmd = f"echo '{rule}' | sudo tee -a {audit_rules_file} > /dev/null"
            serveur.exec_command(modify_cmd)
        
        # Recharger les règles d'audit pour appliquer les changements
        print("🔹 Reloading auditd rules...")
        serveur.exec_command("sudo augenrules --load")
    else:
        print("🔹 auditd rules are already configured.")
    
    # 5. Vérification de l'état de auditd après application
    print("🔹 Verifying auditd status...")
    _, stdout, stderr = serveur.exec_command("sudo systemctl status auditd")
    if "active (running)" in stdout.read().decode():
        print("✅ auditd is running successfully.")
    else:
        print("❌ auditd failed to start.")
        return "Failed"
    
    # 6. Validation : Vérifier si les règles d'audit sont bien appliquées
    print("🔹 Validating auditd rules application...")
    _, stdout, stderr = serveur.exec_command("sudo auditctl -l")
    if all(rule in stdout.read().decode() for rule in audit_rules):
        print("✅ All auditd rules are applied correctly.")
        #update report
        update_report('renforce', 'logging', 'R71')
    else:
        print("❌ Some auditd rules are missing or misconfigured.")
        return "Failed"
    
   
########################### Fin niveau renforcé   ################################




# ============================
# FONCTION PRINCIPALE RESEAU
# ============================

def apply_logging(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    fix_results = {}

    rules = {
        "logging": {
               "renforce": {
                "R71": (apply_R71, "Ensure secure and complete logging configuration"),
                "R72": (apply_R72, "Ensure service log protection against unauthorized access or modification"),
                "R73": (apply_R73, "Ensure auditd is configured properly for system activity logging")
            }
        }
    }

    if niveau in rules["logging"]:
        for rule_id, (function, comment) in rules["logging"][niveau].items():
            print(f"-> Application de la règle {rule_id} : {comment}")
            fix_results[rule_id] = function(serveur, report_data)

    print(f"\n✅ Corrections applied -loggin- Niveau {niveau.upper()}")
   