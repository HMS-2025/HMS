#!/bin/bash

# Chemin vers le fichier YAML
YAML_FILE="recommandations.yaml"

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

  echo "Mises à jour régulières configurées."
}

# Fonction pour appliquer la règle R62 : Désactiver les services non nécessaires
apply_R62() {
    echo "Application de la règle R62 : Désactivation des services non nécessaires..."

    # Liste des services non nécessaires
    services_to_disable=("cups.service" "bluetooth.service" "avahi-daemon.service" "rpcbind.service" "samba.service" "nfs.service")

    # Désactivation des services non nécessaires
    for service in "${services_to_disable[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "Le service $service est actif, arrêt et désactivation..."
            systemctl stop "$service"
            systemctl disable "$service"
        else
            echo "Le service $service est déjà désactivé."
        fi
    done
}


# Fonction pour appliquer la règle R68 : Protéger les mots de passe stockés
apply_R68() {
  # 1. Restreindre les droits d'accès sur le fichier /etc/shadow
  echo "Restreindre les droits d'accès sur /etc/shadow"
  
  # Vérifier et appliquer les permissions -rw-r-----
  sudo chmod 640 /etc/shadow || { echo "Erreur lors de la modification des permissions sur /etc/shadow"; exit 1; }
  sudo chown root:shadow /etc/shadow || { echo "Erreur lors du changement de propriétaire du fichier /etc/shadow"; exit 1; }

  # 2. Hacher les mots de passe avec SHA-256
  echo "Hacher les mots de passe avec SHA-256"
  
  # Parcourir les utilisateurs et re-hacher leurs mots de passe avec SHA-256
  # Utiliser 'passwd' pour modifier les mots de passe
  for user in $(cut -d: -f1 /etc/passwd); do
    echo "Mise à jour du mot de passe pour l'utilisateur $user"
    sudo passwd --stdin $user || { echo "Erreur lors de la mise à jour du mot de passe de $user"; exit 1; }
  done

  # Mettre à jour les mots de passe avec SHA-256 dans /etc/shadow
  sudo sed -i 's/^\([^\:]*\:[^\:]*\):/\\1:$6$/' /etc/shadow || { echo "Erreur lors de la mise à jour des hachages dans /etc/shadow"; exit 1; }

  echo "Règle R68 appliquée avec succès."
}

# Fonction pour appliquer la règle R80 : Réduire la surface d’attaque des services réseau
apply_R80() {
    echo "Application de la règle R80 : Réduction de la surface d'attaque des services réseau..."

    # Liste des services autorisés
    allowed_services=("ssh" "ntp" "dns")

    # Liste des services non autorisés
    disallowed_services=("netcat" "telnet" "ftp" "rlogin" "rexec")

    # Désactivation des services non autorisés
    for service in "${disallowed_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "Le service $service est actif, arrêt et désactivation..."
            systemctl stop "$service"
            systemctl disable "$service"
        else
            echo "Le service $service est déjà désactivé."
        fi
    done

    # Vérification des services autorisés
    for service in "${allowed_services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            echo "Le service $service n'est pas actif, activation..."
            systemctl start "$service"
            systemctl enable "$service"
        else
            echo "Le service $service est déjà actif."
        fi
    done
}



# Fonction pour appliquer une règle générique en fonction de son nom
apply_rule() {
  local rule_name="$1"

  case "$rule_name" in
    "R30")
      apply_R30
      ;;
    "R31")
      apply_R31
      ;;
    "R56")
      apply_R56
      ;;
    "R58")
      apply_R58
      ;;
    "R59")
      apply_R59
      ;;
    "R61")
      apply_R61
      ;;
    "R62")
      apply_R62
      ;;
    "R68")
      apply_R68
      ;;
    "R80")
      apply_R80
      ;;
    *)
      echo "Règle inconnue : $rule_name"
      ;;
  esac
}

# Fonction pour parcourir et appliquer les recommandations selon le YAML
apply_recommendations() {
  # Lire toutes les règles à partir du fichier YAML
  rules=$(yq eval '. | keys' "$YAML_FILE")
  
  # Pour chaque règle, si 'appliquer' est à false, appeler la fonction correspondante
  for rule in $rules; do
    apply_status=$(yq eval ".${rule}.appliquer" "$YAML_FILE")
    
    if [ "$apply_status" == "false" ]; then
      echo "Application de la règle $rule..."
      apply_rule "$rule"
    else
      echo "Règle $rule non appliquée (appliquer: true)."
    fi
  done
}

# Appel de la fonction principale
#apply_recommendations

