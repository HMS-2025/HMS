import subprocess
import yaml
import os

def lock_user_account(user):
    print(f"Verrouillage du compte utilisateur {user}...")
    try:
        subprocess.check_call(['sudo', 'passwd', '-l', user])
    except subprocess.CalledProcessError:
        print(f"Erreur lors du verrouillage du compte {user}")
        exit(1)

def disable_user_shell(user):
    print(f"Changement du shell pour l'utilisateur {user} à /usr/sbin/nologin...")
    try:
        subprocess.check_call(['sudo', 'usermod', '-s', '/usr/sbin/nologin', user])
    except subprocess.CalledProcessError:
        print(f"Erreur lors du changement du shell pour {user}")
        exit(1)

def delete_user_account(user):
    print(f"Suppression du compte utilisateur {user}...")
    try:
        subprocess.check_call(['sudo', 'userdel', '-r', user])
    except subprocess.CalledProcessError:
        print(f"Erreur lors de la suppression du compte {user}")
        exit(1)

def apply_R30(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)
    
    users_detected = data.get('R30', {}).get('elements_detectes', [])
    if not users_detected:
        print("Aucun utilisateur à désactiver dans la règle R30.")
        return
    
    for user in users_detected:
        # Exemple de verrouillage du compte, tu peux choisir l'action à appliquer ici
        lock_user_account(user)

def apply_R31():
    print("Application de la politique de mots de passe robustes...")
    try:
        pam_file = "/etc/pam.d/common-password"
        with open(pam_file, 'r+') as file:
            if "pam_pwquality.so" not in file.read():
                file.write("\npassword requisite pam_pwquality.so retry=3 minlen=12 difok=3\n")
                print(f"Ajout de la politique pam_pwquality.so dans {pam_file}")
            else:
                print("La politique pam_pwquality.so est déjà présente.")
        
        login_defs = "/etc/login.defs"
        with open(login_defs, 'r+') as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                if line.startswith("PASS_MAX_DAYS"):
                    lines[i] = "PASS_MAX_DAYS   90\n"
                    break
            else:
                lines.append("PASS_MAX_DAYS   90\n")
            
            with open(login_defs, 'w') as file_out:
                file_out.writelines(lines)
            print("La durée maximale de validité des mots de passe a été définie à 90 jours.")
        
        faillock_conf = "/etc/security/faillock.conf"
        with open(faillock_conf, 'r+') as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                if line.startswith("deny="):
                    lines[i] = "deny=3\n"
                    break
            else:
                lines.append("deny=3\n")
            
            with open(faillock_conf, 'w') as file_out:
                file_out.writelines(lines)
            print("Le nombre de tentatives échouées avant verrouillage a été défini à 3.")
    
    except Exception as e:
        print(f"Erreur lors de l'application de la politique de mots de passe robustes: {e}")
        exit(1)

def apply_R56(elements_detectes):
    print("Désactivation des permissions setuid et setgid sur les fichiers suivants :")
    for file in elements_detectes:
        if os.path.isfile(file):
            print(f"Modification des permissions sur : {file}")
            subprocess.check_call(['chmod', 'u-s,g-s', file])
        else:
            print(f"Fichier non trouvé : {file}")
    print("Les permissions setuid et setgid ont été supprimées sur les fichiers listés.")

def apply_R58():
    allowed_packages = ["openssh-server", "curl", "vim"]
    installed_packages = subprocess.check_output(['dpkg', '-l'], universal_newlines=True)
    
    for pkg in installed_packages.splitlines():
        pkg_name = pkg.split()[1]
        if pkg_name not in allowed_packages:
            print(f"Le paquet {pkg_name} n'est pas autorisé. Suppression en cours...")
            subprocess.check_call(['sudo', 'apt-get', 'remove', '--purge', '-y', pkg_name])

def apply_R59():
    allowed_repos = ["http://security.ubuntu.com/ubuntu", "http://archive.ubuntu.com/ubuntu"]
    sources_files = ["/etc/apt/sources.list"] + [f for f in os.listdir("/etc/apt/sources.list.d") if f.endswith('.list')]
    
    for file in sources_files:
        with open(file, 'r') as f:
            lines = f.readlines()
        
        with open(file, 'w') as f:
            for line in lines:
                if any(repo in line for repo in allowed_repos):
                    f.write(line)
                else:
                    print(f"Le dépôt non autorisé trouvé : {line}. Suppression de la ligne...")
    print("Les dépôts non autorisés ont été supprimés.")

def apply_R61():
    print("Vérification des mises à jour régulières...")
    # Vérifier Unattended Upgrades
    try:
        subprocess.check_call(['dpkg-query', '-l', '|', 'grep', 'unattended-upgrades'])
    except subprocess.CalledProcessError:
        print("Unattended Upgrades n'est pas installé.")
    
    # Vérifier les mises à jour via cron
    cron_check = subprocess.check_output(['grep', '-i', 'cron', '/etc/cron.d/*'], universal_newlines=True)
    if not cron_check:
        print("Cron pour les mises à jour non configuré.")
        exit(1)
    
    # Vérification des timers systemd
    systemd_timers = subprocess.check_output(['systemctl', 'list-timers'], universal_newlines=True)
    if not systemd_timers:
        print("Timers systemd non trouvés pour les mises à jour.")
        exit(1)

    print("Mises à jour régulières configurées.")

def apply_R62():
    print("Application de la recommandation R62")
    services_to_disable = [
        "cups.service", "bluetooth.service", "avahi-daemon.service", 
        "rpcbind.service", "samba.service", "nfs.service"
    ]
    
    for service in services_to_disable:
        try:
            subprocess.check_call(['systemctl', 'is-active', '--quiet', service])
            print(f"Le service {service} est actif, arrêt et désactivation...")
            subprocess.check_call(['systemctl', 'stop', service])
            subprocess.check_call(['systemctl', 'disable', service])
        except subprocess.CalledProcessError:
            print(f"Le service {service} est déjà désactivé.")

def apply_R68():
    print("Application de la recommandation R68")
    print("Restreindre les droits d'accès sur /etc/shadow")
    subprocess.check_call(['sudo', 'chmod', '640', '/etc/shadow'])
    subprocess.check_call(['sudo', 'chown', 'root:shadow', '/etc/shadow'])
    
    print("Hacher les mots de passe avec SHA-256")
    subprocess.check_call(['sudo', 'sed', '-i', 's/^\([^\:]*\:[^\:]*\):/\\1:$6$/', '/etc/shadow'])

def apply_R80():
    print("Application de la recommandation R80")
    allowed_services = ["ssh", "ntp", "dns"]
    disallowed_services = ["netcat", "telnet", "ftp", "rlogin", "rexec"]
    
    for service in disallowed_services:
        try:
            subprocess.check_call(['systemctl', 'is-active', '--quiet', service])
            print(f"Le service {service} est actif, arrêt et désactivation...")
            subprocess.check_call(['systemctl', 'stop', service])
            subprocess.check_call(['systemctl', 'disable', service])
        except subprocess.CalledProcessError:
            print(f"Le service {service} est déjà désactivé.")
    
    for service in allowed_services:
        try:
            subprocess.check_call(['systemctl', 'is-active', '--quiet', service])
        except subprocess.CalledProcessError:
            print(f"Le service {service} n'est pas actif, activation...")
            subprocess.check_call(['systemctl', 'start', service])
            subprocess.check_call(['systemctl', 'enable', service])

def apply_rule(rule_name, yaml_file):
    if rule_name == "R30":
        apply_R30(yaml_file)
    elif rule_name == "R31":
        apply_R31()
    elif rule_name == "R56":
        apply_R56()
    elif rule_name == "R58":
        apply_R58()
    elif rule_name == "R59":
        apply_R59()
    elif rule_name == "R61":
        apply_R61()
    elif rule_name == "R62":
        apply_R62()
    elif rule_name == "R68":
        apply_R68()
    elif rule_name == "R80":
        apply_R80()
    else:
        print(f"Règle inconnue : {rule_name}")

def apply_recommendationsMin(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)
    
    for rule, rule_data in data.items():
        if rule_data.get('appliquer') == 'false':
            print(f"Application de la règle {rule}...")
            apply_rule(rule, yaml_file)
        else:
            print(f"Règle {rule} déjà appliquée.")
