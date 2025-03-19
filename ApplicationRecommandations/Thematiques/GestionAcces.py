# Ce fichier et coupé en deux partie (partie minimale et partie [moyen + renforcer])

import yaml


def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R30(yaml_file, client):
    print("Application de la recommandation R30")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    
    users_detected = data["gestion_acces"]["R30"]["detected_elements"]
    
    if not users_detected:
        return None
    
    if not data["gestion_acces"]["R30"]['apply']:
        return None
    else : 
        for user in users_detected:
            client.exec_command(f'sudo passwd -l {user}')
        print("R30 appliquée avec succès")

        #Mettre a jour le fichier 
        update_yaml(yaml_file, 'gestion_acces' , 'R30')


def apply_R53(yaml_file, client):
    print("Application de la recommandation R53")

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    
    fichiers_orphelins = data["gestion_acces"]["R53"]["detected_elements"]

    if not fichiers_orphelins:
        return None
    
    if not data["gestion_acces"]["R53"]['apply']:
        return None
    else : 
        for file in fichiers_orphelins:
            client.exec_command(f'sudo rm -f {file} || sudo rm -r {file}')        
        print("R53 appliquée avec succès")

        #Mettre a jour le fichier 
        update_yaml(yaml_file, 'gestion_acces' , 'R53')

def apply_R56(yaml_file, client):
    print("Application de la recommandation R56")

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    
    uid_gid_files = data["gestion_acces"]["R56"]["detected_elements"]
    
    if not uid_gid_files:
        return None
    
    if not data["gestion_acces"]["R56"]['apply']:
        return None
    else : 
        for file in uid_gid_files:
            client.exec_command(f'sudo chmod u-s {file}')        
            client.exec_command(f'sudo chmod g-s {file}')
            client.exec_command(f'sudo chmod o-s {file}')        
        print("R56 appliquée avec succès")

        #Mettre a jour le fichier 
        update_yaml(yaml_file, 'gestion_acces' , 'R56')

def apply_rule(rule_name, yaml_file, client , level):
    if level == "min" : 
        if rule_name == "R30":
            apply_R30(yaml_file, client)
        elif rule_name == "R53":
            apply_R53(yaml_file, client)
        elif rule_name == "R56":
            apply_R56(yaml_file, client)
    elif level == "moyen" : 
        pass
    else : 
        pass
        
def apply_recommandation_acces(yaml_file, client , level ):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)
            
        if not data or 'gestion_acces' not in data:
            return
        for rule, rule_data in data['gestion_acces'].items():
            if rule_data.get('appliquer', False):
                print(f"Règle {rule} déjà appliquée.")
            else:
                apply_rule(rule, yaml_file, client , level)
                
    except FileNotFoundError:
        print(f"Fichier {yaml_file} non trouvé.")
    except yaml.YAMLError as e:
        print(f"Erreur lors de la lecture du fichier YAML : {e}")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite : {e}")

######----------------------------------------PARTIE INTER--------------------------------------------------------------------------------------------------######


import yaml
import os

# ============================
# Fonction utilitaire commune
# ============================
def execute_ssh_command(serveur, command):
    """Exécute une commande SSH sur le serveur distant et retourne la sortie."""
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# ============================
# Fonction de sauvegarde YAML
# ============================
def save_yaml_fix_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportCorrections"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("corrections:\n")

        for rule_id, status in data.items():
            for thematique, niveaux in rules.items():
                if niveau in niveaux and rule_id in niveaux[niveau]:
                    comment = niveaux[niveau][rule_id][1]
                    file.write(f"  {rule_id}:  # {comment} ({thematique})\n")
                    file.write(f"    status: {status}\n")

    print(f"✅ Rapport des corrections généré : {output_path}")

# ============================
# Gestion des accès - Correctifs
# ============================
def apply_r30(serveur, report):
    r30_data = report.get("gestion_acces", {}).get("R30", {})
    if not r30_data.get("apply", False):
        print("✅ R30 : Aucune action nécessaire.")
        return "Conforme"

    inactive_users = r30_data.get("detected_elements", [])
    if not inactive_users or inactive_users == "None":
        print("✅ Aucun compte inutilisé à désactiver.")
        return "Conforme"

    for user in inactive_users:
        print(f"🔒 Désactivation du compte {user}...")
        execute_ssh_command(serveur, f"sudo usermod --expiredate 1 {user}")

    print("✅ R30 : Tous les comptes inactifs ont été désactivés.")
    return "Appliqué"

def apply_r53(serveur, report):
    r53_data = report.get("gestion_acces", {}).get("R53", {})
    if not r53_data.get("apply", False):
        print("✅ R53 : Aucune action nécessaire.")
        return "Conforme"

    orphan_files = r53_data.get("detected_elements", [])
    if not orphan_files or orphan_files == "None":
        print("✅ Aucun fichier sans propriétaire détecté.")
        return "Conforme"

    for file_path in orphan_files:
        print(f"🛠️ Attribution du fichier {file_path} à root...")
        execute_ssh_command(serveur, f"sudo chown root:root {file_path}")

    print("✅ R53 : Tous les fichiers sans propriétaire ont été corrigés.")
    return "Appliqué"

def apply_r56(serveur, report):
    r56_data = report.get("gestion_acces", {}).get("R56", {})
    if not r56_data.get("apply", False):
        print("✅ R56 : Aucune action nécessaire.")
        return "Conforme"

    dangerous_files = r56_data.get("detected_elements", [])
    if not dangerous_files or dangerous_files == "None":
        print("✅ Aucun fichier avec setuid/setgid problématique détecté.")
        return "Conforme"

    for file_path in dangerous_files:
        print(f"🛠️ Suppression des permissions setuid/setgid sur {file_path}...")
        execute_ssh_command(serveur, f"sudo chmod -s {file_path}")

    print("✅ R56 : Tous les fichiers dangereux ont été sécurisés.")
    return "Appliqué"



#############################################################################################
#                                                                                           #
#                    Application des recommandations moyennes                               #    
#                                                                                           #
#############################################################################################
# Charger les références depuis Reference_min.yaml ou Reference_Moyen.yaml
def load_report_yaml(niveau):
    """Charge le fichier de référence correspondant au niveau choisi (min ou moyen)."""
    file_path = f"./GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            report = yaml.safe_load(file)
        return report or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}
    
def load_reference_data_yaml(niveau):
    """Charge le fichier de référence correspondant au niveau choisi (min ou moyen)."""
    file_path = f"./AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            report = yaml.safe_load(file)
        return report or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}

def update_report(data):
    report_path = f"./GenerationRapport/RapportAnalyse/analyse_moyen.yml"
    with open(report_path, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)


def apply_R34(serveur,report):
    """Applique les configurations réseau IPv4 recommandées par l'ANSSI."""

    expected_service_account_to_disable=["www-data", "named","postgres","mysql","backup","lp","irc","games","nobody","mail","systemd-network","proxy","tcpdump","syslog"]    


    if report.get("gestion_acces", {}).get("R34", {}).get("apply", True):
        r34_detected_elements=report.get("gestion_acces", {}).get("R34", {}).get("detected_elements", [])
        print("\n⚠️   Appling rule 34 for disabling services account   ⚠️\n")
        #desactivations des comptes
        for service_account in expected_service_account_to_disable:
            if service_account in r34_detected_elements:
               serveur.exec_command(f"sudo passwd -l {service_account}")        
             
        
        #Mis à jours du rapport et sauve garde du report
        report["gestion_acces"]["R34"]["apply"]=False
        report["gestion_acces"]["R34"]["status"]="Conforme"
        # Mise à jour des comptes détectés après application
        remaining_accounts = set(r34_detected_elements) - set(expected_service_account_to_disable)
        report["gestion_acces"]["R34"]["detected_elements"] = list(remaining_accounts)        
        update_report(report)        
        print("✅ The rule 34 is successffully applied and report updated 📁")
    else:
        return None

# #  Cette fonction applique bien la regle sauf que l'analyse  done false tjrs.
#Regle 39
def apply_R39(serveur, report, reference_data):
    """Applique la règle R39 en modifiant les directives sudoers."""

    #directives_expected = {"Defaults noexec","Defaults requiretty","Defaults use_pty","Defaults umask=0027","Defaults ignore_dot","Defaults env_reset"}

    directives_expected=reference_data.get("gestion_acces", {}).get("R39", {}).get("expected", {}).get("sudo_directives",[])

    r39_detected_elements = report.get("gestion_acces", {}).get("R39", {}).get("detected_elements", [])

    if report.get("gestion_acces", {}).get("R39", {}).get("apply",True):
        print("\n⚠️   Application of rule 39 (Modify sudo configuration directives)   ⚠️\n")

        # Sauvegarde du fichier sudoers si ce n'est pas encore fait
        serveur.exec_command("sudo cp -n /etc/sudoers /etc/sudoers.htms")

        # Normalisation des éléments détectés avant toute comparaison
        normalized_r39_detected_elements = [' '.join(line.split()) for line in r39_detected_elements]

        all_lines_commented = []  # Liste des lignes qui ont été commentées

        for line in normalized_r39_detected_elements:
            if line not in directives_expected:
                # Utiliser sed avec une regex plus souple pour matcher indépendamment des espaces/tabulations
                escaped_line = line.replace(" ", "[[:space:]]*")
                sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"

                serveur.exec_command(sed_command)
                all_lines_commented.append(line)  

        # Mise à jour du rapport
        report["gestion_acces"]["R39"]["apply"] = False
        report["gestion_acces"]["R39"]["status"] = "Conforme"

        # Mise à jour des éléments détectés après application de la règle
        remaining_elements = set(normalized_r39_detected_elements) - set(all_lines_commented)
        report["gestion_acces"]["R39"]["detected_elements"] = list(remaining_elements)

        # Sauvegarder le rapport mis à jour
        update_report(report)
        print("✅ The rule 39 is successffully applied and report updated 📁")
        

##l'application se fait bien mais l'analyse donne false
"""L'application de la règle R40 vise à restreindre l'accès sudo aux seuls utilisateurs autorisés, tels que root, ubuntu, administrateur, et %admin, tout en conservant les privilèges spécifiques pour d'autres utilisateurs ayant des restrictions sur certaines commandes. Si un utilisateur non autorisé dispose de privilèges sudo complets (ALL), ces privilèges sont révoqués. En revanche, si un utilisateur possède des restrictions spécifiques (par exemple, l'accès à /usr/bin/apt), sa configuration est préservée. Le fichier /etc/sudoers est modifié en conséquence, et un rapport est mis à jour pour refléter l'état de la conformité.
"""

def apply_R40(serveur, report):
    """Applique la règle R40 en restreignant l'accès sudo aux seuls utilisateurs root et ubuntu,
       en préservant les privilèges spécifiques pour d'autres utilisateurs."""
    # Liste des utilisateurs autorisés à utiliser sudo
    allowed_users = ["root", "ubuntu", "administrateur", "%admin","sudo"]

    # Détection des éléments existants dans le rapport
    detected_elements = report.get("gestion_acces", {}).get("R40", {}).get("detected_elements", [])
    if report.get("gestion_acces", {}).get("R40", {}).get("apply", True):
        print("\n⚠️   Application of rule 40 (restrict sudo using to none privilege users)   ⚠️\n")
        if not detected_elements:
            print("Aucun élément détecté pour la règle R40.")
            print(" [✔] Rule 40 : Nothing elements are detected for sudo restrictions access")
            return

        # Sauvegarde du fichier sudoers si ce n'est pas déjà fait
        serveur.exec_command("sudo cp -n /etc/sudoers /etc/sudoers.htms")

        # Liste des lignes à modifier
        all_lines_modified = []

        for line in detected_elements:
            # 1) Extraire l'utilisateur et la commande
            parts = line.split("ALL=(ALL:ALL)")
            
            # Si la ligne est valide et qu'elle contient "ALL=(ALL:ALL)"
            if len(parts) == 2:
                username = parts[0].strip()  # L'utilisateur est avant "ALL=(ALL:ALL)"
                command = parts[1].strip()  # La commande est après "ALL=(ALL:ALL)"
                
                # 2) Vérifier si l'utilisateur est autorisé
                if username in allowed_users:
                    # Si l'utilisateur est autorisé, on ne fait rien
                    continue

                # 3) Vérifier si la commande est "ALL" et s'il n'y a rien d'autre après
                if command == "ALL":
                    # Restreindre les privilèges de l'utilisateur
                    modified_line = f"{username} ALL=(ALL) NOPASSWD: /usr/bin/false"  # Aucune commande sudo autorisée
                    sed_command = f"sudo sed -i 's|^{line}$|{modified_line}|' /etc/sudoers"
                    serveur.exec_command(sed_command)
                    all_lines_modified.append(line)
                else:
                    # Si la commande contient des restrictions spécifiques, on garde la ligne inchangée
                    continue    
        # Mise à jour du rapport
        report["gestion_acces"]["R40"]["apply"] = False
        report["gestion_acces"]["R40"]["status"] = "Conforme"

        # Mise à jour des éléments détectés après application de la règle
        remaining_elements = set(detected_elements) - set(all_lines_modified)
        report["gestion_acces"]["R40"]["detected_elements"] = list(remaining_elements)

        # Sauvegarder le rapport mis à jour
        update_report(report)
        print("✅ Thes rule 40 is successffully applied and report updated 📁")


#Regle 42
def apply_R42(serveur, report):
    """Applique la règle R42 en supprimant les spécifications de négation dans sudoers."""
    
    # Détection des éléments existants dans le rapport
    detected_elements = report.get("gestion_acces", {}).get("R42", {}).get("detected_elements", [])
    if report.get("gestion_acces", {}).get("R42", {}).get("apply", True):
        print("\n⚠️   Appling rule 42 (Ban negations in sudo specifications)   ⚠️\n")
        if not detected_elements:
            print(" [✔] Rule 42 : Nothing elements are detected for negation sudo specifications")
            return

        # Sauvegarde du fichier sudoers avant modification
        serveur.exec_command("sudo cp -n /etc/sudoers /etc/sudoers.htms")

        # Liste des modifications effectuées
        all_lines_modified = []

        for line in detected_elements:
            if "!" in line:  # Vérifier si la ligne contient une négation
                # Supprimer les parties contenant "!"
                modified_line = " ".join(word for word in line.split() if "!" not in word)

                # Appliquer la modification avec sed
                sed_command = f"sudo sed -i 's|^{line}$|{modified_line}|' /etc/sudoers"
                serveur.exec_command(sed_command)
                all_lines_modified.append(line)

        # Mise à jour du rapport après modification
        report["gestion_acces"]["R42"]["apply"] = False
        report["gestion_acces"]["R42"]["status"] = "Conforme"

        # Mise à jour des éléments détectés après correction
        remaining_elements = set(detected_elements) - set(all_lines_modified)
        report["gestion_acces"]["R42"]["detected_elements"] = list(remaining_elements)

        # Sauvegarder le rapport mis à jour
        update_report(report)
        print("✅ The Rule 42 is successfully applied and report updated 📁")



#Regle 43
def apply_R43(serveur, report):
    """Applique la règle R43 avec une meilleure recherche de motifs et gestion des espaces/tabulations."""
    # Liste des utilisateurs privilégiés (à ne pas modifier)
    admin_users = {'root', 'admin', 'sudo', 'administrateur', 'ubuntu','%admin', '%sudo'}
    r43_detected_elements = report.get("gestion_acces", {}).get("R43", {}).get("detected_elements", [])

    if report.get("gestion_acces", {}).get("R43", {}).get("apply", True):
        print("\n⚠️   Appling rule 43 (Specify arguments in sudo specifications)   ⚠️\n")
        serveur.exec_command("sudo cp -n /etc/sudoers /etc/sudoers.htms")
        all_lines_modified = []

        for line in r43_detected_elements:
            user = line.split()[0]

            # Si l'utilisateur est un utilisateur privilégié, on ne fait aucune modification
            if user in admin_users:
               continue

            # Modifications de la ligne, uniquement pour les utilisateurs non privilégiés
            modified_line = restrict_sudo_arguments(line)

            # Remplacer les espaces multiples par [[:space:]]+ pour capturer tabulations et espaces
            
            escaped_line = line.replace(" ", "[[:space:]]*")            
            # Commande sed pour effectuer le remplacement
            sed_command = f"sudo sed -i 's|^{escaped_line}$|{modified_line}|' /etc/sudoers"
            serveur.exec_command(sed_command)
            all_lines_modified.append(line)          
            

        # Mise à jour du rapport après application des modifications
        report["gestion_acces"]["R43"]["apply"] = False
        report["gestion_acces"]["R43"]["status"] = "Conforme"
        remaining_elements = set(r43_detected_elements) - set(all_lines_modified)
        report["gestion_acces"]["R43"]["detected_elements"] = list(remaining_elements)

        update_report(report)
        print("✅ The rule R43 is ssucessfully applied and report updated 📁")

def restrict_sudo_arguments(line):
    """Restreint les arguments d'une ligne sudo à des commandes spécifiques."""
    # Exemple de restriction d'arguments pour une commande
    restricted_commands = {
        "/bin/ls": "/bin/ls /home/* /var/www/* /etc/*",  # Lister les fichiers dans des répertoires spécifiques
        "/bin/cp": "/bin/cp /etc/* /home/backup/",  # Copie de fichiers uniquement vers des répertoires spécifiques
        "/bin/mv": "/bin/mv /var/log/* /home/logs_backup/",  # Déplacer des fichiers de logs vers un répertoire de sauvegarde
        "/bin/rm": "/bin/rm -f /var/log/*.log",  # Suppression des fichiers de logs (précaution)
        "/usr/bin/ps": "/usr/bin/ps aux",  # Affichage des processus en cours
        "/usr/bin/top": "/usr/bin/top -b -n 1",  # Afficher l'utilisation du système dans un format lisible
        "/usr/bin/tar": "/usr/bin/tar -czf /home/backup/archives.tar.gz /home/*",  # Créer une archive tar spécifique
        "/usr/bin/df": "/usr/bin/df -h",  # Vérifier l'espace disque
        "/usr/bin/free": "/usr/bin/free -m",  # Vérifier l'utilisation de la mémoire
        "/usr/sbin/reboot": "/usr/sbin/reboot",  # Reboot du serveur (restreint à l'exécution sans arguments supplémentaires)
        "/usr/sbin/shutdown": "/usr/sbin/shutdown -h now",  # Arrêt immédiat du serveur
        "/usr/sbin/service": "/usr/sbin/service apache2 restart",  # Redémarrer Apache (peut être restreint pour d'autres services)
        "/usr/sbin/systemctl": "/usr/sbin/systemctl restart apache2",  # Redémarrer Apache via systemctl
        "/usr/sbin/useradd": "/usr/sbin/useradd -m -s /bin/bash",  # Créer un utilisateur avec un shell sécurisé
        "/usr/sbin/usermod": "/usr/sbin/usermod -aG sudo",  # Ajouter un utilisateur au groupe sudo
        "/usr/sbin/groupadd": "/usr/sbin/groupadd admins",  # Ajouter un groupe admins (restreint à certains groupes)
        "/usr/bin/vi": "/usr/bin/vi /etc/hosts",  # Modifier des fichiers spécifiques avec vi (utilisation sécurisée)
        "/usr/bin/grep": "/usr/bin/grep 'pattern' /var/log/syslog",  # Rechercher dans les fichiers de log
    }

    # Restreindre les autorisations globales "ALL=(ALL:ALL) ALL"
    if "ALL=(ALL:ALL) ALL" in line:
        # Remplacer ALL par une commande spécifique et maintenir la structure de la ligne
        return line.replace("ALL=(ALL:ALL) ALL", "ALL=(ALL:ALL) /bin/ls /home/* /var/www/* /etc/*") 
    
    # Si une commande est présente dans la ligne, la remplacer par sa version restreinte
    for command, restricted_args in restricted_commands.items():
        if command in line:
            # Remplacer la ligne par la commande restreinte
            return line.replace(command, restricted_args)

    return line  # Si la commande n'est pas dans les restrictions, retourner la ligne inchangée



#regle 44
def apply_R44(serveur, report):
    """Applique la règle R44 (Edit files securely with sudo)"""
    
    # Liste des éditeurs à remplacer par sudoedit
    editors = [
    'nano', 'vim', 'vi', 'emacs', 'pico', 'gedit', 'kate', 'leafpad', 'micro', 'joe', 'sublime', 'atom', 'gedit'
    ]

    r44_detected_elements = report.get("gestion_acces", {}).get("R44", {}).get("detected_elements", [])

    if report.get("gestion_acces", {}).get("R44", {}).get("apply", True):
        print("\n⚠️   Appling rule 44 (Edit files securely with sudo)   ⚠️\n")

        serveur.exec_command("sudo cp -n /etc/sudoers /etc/sudoers.htms")
        all_lines_modified = []

        for line in r44_detected_elements:
            # Rechercher si la ligne contient un éditeur
            for editor in editors:
                if editor in line:
                    modified_line = line.replace(editor, "sudoedit")
                    # Remplacer la ligne dans sudoers
                    escaped_line = line.replace(" ", "[[:space:]]*")  # Gestion des espaces/tabulations
                    sed_command = f"sudo sed -i 's|^{escaped_line}$|{modified_line}|' /etc/sudoers"
                    serveur.exec_command(sed_command)
                    all_lines_modified.append(line)
                    print(f"🛠️  Remplacement effectué: {line} => {modified_line}")
                    break  # Pas besoin de vérifier d'autres éditeurs

        # Mise à jour du rapport après application des modifications
        report["gestion_acces"]["R44"]["apply"] = False
        report["gestion_acces"]["R44"]["status"] = "Conforme"
        remaining_elements = set(r44_detected_elements) - set(all_lines_modified)
        report["gestion_acces"]["R44"]["detected_elements"] = list(remaining_elements)

        update_report(report)
        print("✅ The rule R44 is ssucessefully applied  and report updated 📁")


def apply_R50(serveur, report,reference_data):
    """Applique la règle R50 en vérifiant et modifiant les permissions des fichiers sensibles."""
   
    #Recuperation of the expected permissions from the reference data
    expected_permissions = {
    entry.rsplit(" ", 1)[0]: entry.rsplit(" ", 1)[1]
    for entry in reference_data.get("R50", {}).get("expected", [])
   }
      
    if report.get("gestion_acces", {}).get("R50", {}).get("apply", True):
        print("\n⚠️   Appling rule 50 (Restrict access permissions to sensitive files and directories)   ⚠️\n")
        #Recuperation of the elements detected
        detected_elements = report.get("gestion_acces", {}).get("R50", {}).get("detected_elements", [])

        if not detected_elements:            
            print(" [✔] Rule 50 : Nothing elements are detected for insecure file editing")
            return

        # Liste des fichiers modifiés
        all_files_modified = []

        # Application des permissions attendues
        for file_path in detected_elements:
            if file_path in expected_permissions:
                # Sauvegarder le fichier avant modification
                backup_command = f"sudo cp -an {file_path} {file_path}.htms"
                serveur.exec_command(backup_command)

                # Modifier les permissions
                chmod_command = f"sudo chmod {expected_permissions[file_path]} {file_path}"
                serveur.exec_command(chmod_command)
                all_files_modified.append(file_path)

        # Mise à jour du rapport après modification
        report["gestion_acces"]["R50"]["apply"] = False
        report["gestion_acces"]["R50"]["status"] = "Conforme"

        # Mise à jour des éléments détectés après correction
        remaining_elements = set(detected_elements) - set(all_files_modified)
        report["gestion_acces"]["R50"]["detected_elements"] = list(remaining_elements)

        # Sauvegarder le rapport mis à jour
        update_report(report)       
        print("✅ The rule 50 is successfully applied and the report is updated 📁")



#Regle 52
def apply_R52(serveur, report,reference_data):
    """Applique la règle R52 en vérifiant et modifiant les permissions des sockets et tubes nommés."""
    print("\n⚠️   Application of rule 52 (Protect named pipes and sockets)   ⚠️\n")

    #Recuperation of the expected permissions from the reference data
    expected_permissions = {
    entry.rsplit(" ", 1)[0]: entry.rsplit(" ", 1)[1]
    for entry in reference_data.get("R52", {}).get("expected", [])
   }

    
    if report.get("gestion_acces", {}).get("R52", {}).get("apply", True):
        # Détection des éléments existants dans le rapport
        detected_elements = report.get("gestion_acces", {}).get("R52", {}).get("detected_elements", [])
        if not detected_elements:
            print("[✔] Rule 52 : Nothing elements are detected for changing permission")
            return

        # Liste des éléments modifiés
        all_elements_modified = []

        # Application des permissions attendues
        for element in detected_elements:
            file_path = element.split()[2]  # Le chemin du fichier est toujours à la troisième position dans la ligne
            if file_path in expected_permissions:
                # Sauvegarder l'élément avant modification
                print(f"The permissions of {file_path} is incorrect. we save and attribute good permissions {expected_permissions[file_path]}.")
                backup_command = f"sudo cp -an {file_path} {file_path}.htms"
                serveur.exec_command(backup_command)

                # Modifier les permissions
                chmod_command = f"sudo chmod {expected_permissions[file_path]} {file_path}"
                serveur.exec_command(chmod_command)
                all_elements_modified.append(file_path)

        # Mise à jour du rapport après modification
        report["gestion_acces"]["R52"]["apply"] = False
        report["gestion_acces"]["R52"]["status"] = "Conforme"

        # Mise à jour des éléments détectés après correction
        remaining_elements = set(detected_elements) - set(all_elements_modified)
        report["gestion_acces"]["R52"]["detected_elements"] = list(remaining_elements)

        # Sauvegarder le rapport mis à jour
        update_report(report)        
        print("✅ The R52 is ssuccessfully applied and  report updated 📁")



#Regle 55
def apply_R55(serveur, report):
    """
    Applique la règle R55 : Isolation des répertoires temporaires des utilisateurs.
    - Vérifie si apply est True
    - Sauvegarde les répertoires détectés
    - Monte les répertoires avec les options de sécurité
    """


    # Vérification si la règle est activée
    if  report.get("gestion_acces", {}).get("R55", {}).get("apply", True): 
        # Récupérer la règle R55 depuis le rapport
        detected_elements = report.get("gestion_acces", {}).get("R55", {}).get("detected_elements", [])
        # Vérification si des éléments ont été détectés
        if not detected_elements:
            print("[✔] Rule 55 : Nothing elements are detected, for isolation.")
            return

        # Appliquer les actions pour chaque répertoire détecté
        for file_path in detected_elements:  # Utilisation des chemins détectés
            # Vérifier si le chemin est un répertoire ou un fichier
            is_directory_command = f"test -d {file_path} && echo 'directory' || echo 'file'"
            stdin, stdout, stderr = serveur.exec_command(is_directory_command)
            is_directory = stdout.read().decode().strip()

            # Sauvegarde avant modification (uniquement si pas déjà sauvegardé)
            backup_command = f"sudo cp -r --no-clobber {file_path} {file_path}.htms"

            # Application de l'isolation (montage sécurisé) selon si c'est un répertoire ou un fichier
            if is_directory == "directory":
                mount_command = f"sudo mount -o bind,noexec,nodev,nosuid {file_path} {file_path}"
            else:
                mount_command = f"echo '{file_path} is a file, nothing mount is applied.'"

            # Exécution des commandes
            for cmd in [backup_command, mount_command]:
                stdin, stdout, stderr = serveur.exec_command(cmd)
                print(stdout.read().decode(), stderr.read().decode())

        print("✅ The R55 is ssuccessfully applied and  report updated 📁")



#Regle 67
def apply_R67(serveur, report, reference_data):
    """
    Affiche les règles PAM détectées (R67) et les règles manquantes avec risques et commandes associées.
    """

    # Vérification si la règle est activée
    if report.get("gestion_acces", {}).get("R67", {}).get("apply", True):      
        print("\n⚠️   Appling rule 67 (PAM authentication))   ⚠️\n")  
        detected_elements = report.get("gestion_acces", {}).get("R67", {}).get("detected_elements", [])
        if not detected_elements:
            print("[✔] Nothing PAM rule are detected for PAM authentication .")
            return

        # Définition des risques associés aux règles
        risks = {
            "account required pam_nologin.so": "🔴 Empêche les connexions non autorisées si /etc/nologin existe.",
            "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close": "🟠 Peut impacter le bon fonctionnement de SELinux.",
            "session required pam_loginuid.so": "🟠 Associe une session à un UID, essentiel pour la traçabilité.",
            "session optional pam_keyinit.so force revoke": "🟡 Sans cette règle, les anciennes clés persistantes ne sont pas révoquées.",
            "session optional pam_motd.so motd=/run/motd.dynamic": "🟡 Affiche des messages dynamiques à la connexion.",
            "session optional pam_motd.so noupdate": "🟡 Empêche la mise à jour automatique du fichier MOTD.",
            "session optional pam_mail.so standard noenv # [1]": "🟡 Informe l'utilisateur des nouveaux mails (optionnel).",
            "session required pam_limits.so": "🟠 Applique les limites utilisateur définies dans /etc/security/limits.conf.",
            "session required pam_env.so # [1]": "🟠 Charge les variables d'environnement système.",
            "session required pam_env.so user_readenv=1 envfile=/etc/default/locale": "🟠 Charge les paramètres de langue et localisation.",
            "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open": "🟠 Active SELinux pour la session.",
            "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=300": "🔴 Bloque l'utilisateur après 5 échecs de connexion.",
            "auth required pam_faillock.so authfail audit deny=5 unlock_time=300": "🔴 Renforce la politique de verrouillage après échecs.",
            "auth optional pam_pwquality.so retry=3 minlen=8 difok=2": "🟠 Renforce la complexité des mots de passe.",
        }

        # Définir les fichiers PAM cibles
        pam_files = {
            "auth": "/etc/pam.d/common-auth",
            "session": "/etc/pam.d/common-session",
            "password": "/etc/pam.d/common-password",
            "account": "/etc/pam.d/common-account",
        }

        # Etape 1 : Affichage des éléments détectés
       # print("[🔎] Règles PAM détectées :")
        #for pam_rule in detected_elements:
           # print(f"   ➜ {pam_rule}")

        # Etape 2 : Affichage des éléments attendus non détectés
        print("\n =============== Règles PAM manquantes (non détectées) ===================")
        expected_elements = reference_data.get("R67", {}).get("expected", {}).get("pam_rules", [])

        for pam_rule in expected_elements:
            if pam_rule not in detected_elements:
                # Identifie le type de la règle pour la répartition dans le bon fichier
                rule_type = "auth" if "auth" in pam_rule else "session" if "session" in pam_rule else "account" if "account" in pam_rule else "password"
                pam_file = pam_files.get(rule_type)

                # Si le fichier est trouvé, on affiche la commande d'application
                if pam_file:
                    print(f"\nDirective PAM:  {pam_rule}")
                    print(f"   ⚠ Risque : {risks.get(pam_rule, '⚠ Risque non documenté.')}")
                    print(f"\nCommande d'application : echo '{pam_rule}' | sudo tee -a {pam_file} > /dev/null")
                    print("\n" + "+" * 100)

""" 
#just for test
def apply_recommandation_acces2(serveur, niveau):
     report = load_report_yaml(niveau)     
     reference_data= load_reference_data_yaml(niveau)
     #apply_R34(serveur,report)
     #apply_R39(serveur, report,reference_data)
     #apply_R40(serveur, report)
     #apply_R42(serveur, report)
     #apply_R43(serveur, report)
     #apply_R44(serveur, report)
     #apply_R50(serveur, report,reference_data)
     #apply_R52(serveur, report,reference_data)
     #apply_R55(serveur, report)
     #apply_R67(serveur, report,reference_data)"""
     
     
     
####################### Fin de de definitions des fonction de gestion d'acess niveau moyen ############################


# ============================
# Fonction principale par niveau pour GESTION ACCÈS
# ============================
def apply_gestion_acces(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    fix_results = {}

    rules = {
        "min": {
            "R30": (apply_r30, "Désactiver les comptes utilisateur inutilisés"),
            "R53": (apply_r53, "Corriger les fichiers sans utilisateur/groupe"),
            "R56": (apply_r56, "Supprimer les setuid/setgid non nécessaires")
        },
        "moyen": {            
            "R34": (apply_R34, "Disable service accounts (non-exhaustive list)"),
            "R39": (apply_R39, "Modify sudo configuration directives"),
            "R40": (apply_R40, "Use non-privileged target users for sudo commands"),
            "R42": (apply_R42, "Ban negations in sudo specifications"),
            "R43": (apply_R43, "Specify arguments in sudo specifications"),
            "R44": (apply_R44, "Edit files securely with sudo"),
            "R50": (apply_R50, "Restrict access permissions to sensitive files and directories"),
            "R52": (apply_R52, "Ensure named pipes and sockets have restricted permissions")
            "R55": (apply_R55, "Isolate user temporary directories")
            "R67": (apply_R67, "Ensure remote authentication via PAM")
        },
        "avancé": {
            # À compléter si besoin
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Application de la règle {rule_id} : {comment}")
            fix_results[rule_id] = function(serveur, report_data)

    # Génération rapport YAML + HTML si besoin
    save_yaml_fix_report(fix_results, f"fixes_{niveau}_gestion_acces.yml", rules, niveau)

    yaml_path = f"GenerationRapport/RapportCorrections/fixes_{niveau}_gestion_acces.yml"
    html_path = f"GenerationRapport/RapportCorrectionsHTML/fixes_{niveau}_gestion_acces.html"

    # Si tu as déjà la fonction :
    # generate_html_report(yaml_path, html_path, niveau)
    print(f"\n✅ Correctifs appliqués - GESTION ACCÈS - Niveau {niveau.upper()}")
