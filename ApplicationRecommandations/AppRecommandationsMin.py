#!/bin/bash

# Chemin vers le fichier YAML
YAML_FILE="YAML_File.yaml"

# Fonction pour verrouiller un compte utilisateur (R30)
lock_user_account() {
  local user="$1"
  echo "Verrouillage du compte utilisateur $user..."
  sudo passwd -l "$user" || { echo "Erreur lors du verrouillage du compte $user"; exit 1; }
}

# Fonction pour changer le shell d'un utilisateur à /usr/sbin/nologin (R30)
disable_user_shell() {
  local user="$1"
  echo "Changement du shell pour l'utilisateur $user à /usr/sbin/nologin..."
  sudo usermod -s /usr/sbin/nologin "$user" || { echo "Erreur lors du changement du shell pour $user"; exit 1; }
}

# Fonction pour supprimer un compte utilisateur (R30)
delete_user_account() {
  local user="$1"
  echo "Suppression du compte utilisateur $user..."
  sudo userdel -r "$user" || { echo "Erreur lors de la suppression du compte $user"; exit 1; }
}

# Fonction pour appliquer la règle R30 : Désactiver les comptes inutilisés
apply_R30() {
  # Lire la liste des utilisateurs dans 'elements_detectes' depuis le fichier YAML
  users_detected=$(yq eval '.R30.elements_detectes[]' "$YAML_FILE")
  
  if [ -z "$users_detected" ]; then
    echo "Aucun utilisateur à désactiver dans la règle R30."
    return
  fi

  # Applique les actions de désactivation sur chaque utilisateur détecté
  for user in $users_detected; do
    # Verrouiller le compte ou changer le shell ou supprimer le compte
    lock_user_account "$user"  # Exemple, tu peux choisir l'action à appliquer
  done
}
 
# Fonction pour appliquer la règle R31 : Utiliser des mots de passe robustes
apply_R31() {
    echo "Application de la politique de mots de passe robustes..."

    # Définir la politique PAM dans /etc/pam.d/common-password
    PAM_FILE="/etc/pam.d/common-password"
    if ! grep -q "pam_pwquality.so" "$PAM_FILE"; then
        echo "Ajout de la politique pam_pwquality.so dans $PAM_FILE"
        echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3" >> "$PAM_FILE"
    else
        echo "La politique pam_pwquality.so est déjà présente."
    fi

    # Appliquer la politique d'expiration des mots de passe dans /etc/login.defs
    LOGIN_DEFS="/etc/login.defs"
    if ! grep -q "^PASS_MAX_DAYS" "$LOGIN_DEFS"; then
        echo "PASS_MAX_DAYS   90" >> "$LOGIN_DEFS"
        echo "La durée maximale de validité des mots de passe a été définie à 90 jours."
    else
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$LOGIN_DEFS"
        echo "La durée maximale de validité des mots de passe a été mise à jour à 90 jours."
    fi
YAML_FILE
    # Appliquer la politique de verrouillage de compte (faillock)
    FAILLOCK_CONF="/etc/security/faillock.conf"
    if ! grep -q "^deny=" "$FAILLOCK_CONF"; then
        echo "deny=3" >> "$FAILLOCK_CONF"
        echo "Le nombre de tentatives échouées avant verrouillage a été défini à 3."
    else
        sed -i 's/^deny=.*/deny=3/' "$FAILLOCK_CONF"
        echo "Le nombre de tentatives échouées avant verrouillage a été mis à 3."
    fi
}

# Fonction pour appliquer la règle R56 : Désactiver les fichiers exécutables avec les droits spéciaux setuid et setgid
apply_R56() {
  # Assumons que "elements_detectes" contient une liste de fichiers avec setuid ou setgid
  echo "Désactivation des permissions setuid et setgid sur les fichiers suivants :"

  # Parcours des fichiers dans elements_detectes
  for file in "${elements_detectes[@]}"; do
    if [ -f "$file" ]; then
      # Vérifier et supprimer les permissions setuid et setgid sur chaque fichier
      echo "Modification des permissions sur : $file"
      chmod u-s,g-s "$file"
    else
      echo "Fichier non trouvé : $file"
    fi
  done

  echo "Les permissions setuid et setgid ont été supprimées sur les fichiers listés."
}

# Fonction pour appliquer la règle R58 : N'installer que les paquets nécessaires
apply_R58() {
  # Paquets autorisés
  allowed_packages=("openssh-server" "curl" "vim")

  # Lister les paquets installés
  installed_packages=$(dpkg -l | grep '^ii' | awk '{print $2}')

  for pkg in $installed_packages; do
    # Vérifier si le paquet est dans la liste des paquets autorisés
    if [[ ! " ${allowed_packages[@]} " =~ " ${pkg} " ]]; then
      echo "Le paquet $pkg n'est pas autorisé. Suppression en cours..."
      sudo apt-get remove --purge -y "$pkg" || { echo "Erreur lors de la suppression du paquet $pkg"; exit 1; }
    fi
  done
}

# Fonction pour appliquer la règle R59 : Utiliser des dépôts de paquets de confiance
apply_R59() {
  # Dépôts autorisés
  allowed_repos=("http://security.ubuntu.com/ubuntu" "http://archive.ubuntu.com/ubuntu")

  # Fichiers de sources APT
  sources_files=("/etc/apt/sources.list" /etc/apt/sources.list.d/*)

  # Parcourir tous les fichiers de sources
  for file in "${sources_files[@]}"; do
    if [[ -f "$file" ]]; then
      echo "Vérification des dépôts dans le fichier $file"
      
      # Lire chaque ligne du fichier
      while read -r line; do
        # Si la ligne ne correspond pas à un dépôt autorisé
        if [[ ! " ${allowed_repos[@]} " =~ " ${line} " ]]; then
          echo "Le dépôt non autorisé trouvé : $line. Suppression de la ligne..."
          # Supprimer la ligne contenant le dépôt non autorisé
          sudo sed -i "/${line//\//\\/}/d" "$file" || { echo "Erreur lors de la suppression de la ligne"; exit 1; }
        fi
      done < "$file"
    fi
  done
}



# Fonction pour appliquer la règle R61 : Effectuer des mises à jour régulières
apply_R61() {
  echo "Vérification des mises à jour automatiques..."
  
  # Vérifier Unattended Upgrades
  dpkg-query -l | grep "unattended-upgrades" || { echo "Unattended Upgrades n'est pas installé."; exit 1; }

  # Vérifier les mises à jour via cron
  cron_check=$(grep -i "cron" /etc/cron.d/*)
  if [[ -z "$cron_check" ]]; then
    echo "Cron pour les mises à jour non configuré."
    exit 1
  fi

  # Vérification des timers systemd
  systemd-timers=$(systemctl list-timers)
  if [[ -z "$systemd-timers" ]]; then
    echo "Timers systemd non trouvés pour les mises à jour."
    exit 1
  fi

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
