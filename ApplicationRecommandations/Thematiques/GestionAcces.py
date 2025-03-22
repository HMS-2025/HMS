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
        print("-  R30 : Aucune action nécessaire.")
        return "Compliant"
    inactive_users = r30_data.get("detected_elements", [])
    if not inactive_users or inactive_users == "None":
        print("-  Aucun compte inutilisé à désactiver.")
        return "Compliant"
    for user in inactive_users:
        print(f"- Désactivation du compte {user}...")
        execute_ssh_command(serveur, f'sudo passwd -l {user}')
    
    print("-  R30 : Tous les comptes inactifs ont été désactivés.")
    update_report('min' , 'access_management' , 'R30')

def apply_r53(serveur, report):

    r53_data = report.get("R53", {})
    if not r53_data.get("apply", False):
        print("-  R53 : Aucune action nécessaire.")
        return "Compliant"
    orphan_files = r53_data.get("detected_elements", [])
    if not orphan_files or orphan_files == "None":
        print("-  Aucun fichier sans propriétaire détecté.")
        return "Compliant"
    for file_path in orphan_files:
        print(f"-  Attribution du fichier {file_path} à root...")
        execute_ssh_command(serveur, f"sudo chown root:root {file_path}")
    
    print("-  R53 : Tous les fichiers sans propriétaire ont été corrigés.")
    update_report('min' ,'access_management' , 'R53')

def apply_r56(serveur, report):

    r56_data = report.get("R56", {})
    if not r56_data.get("apply", False):
        print("-  R56 : Aucune action nécessaire.")
        return "Compliant"

    dangerous_files = r56_data.get("detected_elements", [])
    if not dangerous_files or dangerous_files == "None":
        print("-  Aucun fichier avec setuid/setgid problématique détecté.")
        return "Compliant"

    for file_path in dangerous_files:
        print(f"-  Suppression des permissions setuid/setgid sur {file_path}...")
        execute_ssh_command(serveur, f"sudo chmod -s {file_path}")

    print("-  R56 : Tous les fichiers dangereux ont été sécurisés.")
    update_report('min' ,'access_management' , 'R56')


def apply_R34(serveur,report):

    r34_data = report.get("R34", {})

    if not r34_data.get("apply", False):
        print("-  R34 : Aucune action nécessaire.")
        return "Compliant"

    r34_detected_elements=r34_data.get("R34", {}).get("detected_elements", [])
    
    for compte in r34_detected_elements : 
        execute_ssh_command(serveur,f"sudo passwd -l {compte}")

    print("-  R34 : Les comptes inactifs ont été désactivé avec succes")
    update_report('moyen' ,'access_management' , 'R34')


def apply_R39(serveur, report):

    r39_data = report.get("R39", {})

    if not r39_data.get("apply", False):
        print("-  R39 : Aucune action nécessaire.")
        return "Compliant"

    # Liste codée en dur des directives attendues
    directives_expected = [
        "Defaults noexec",
        "Defaults requiretty",
        "Defaults use_pty",
        "Defaults umask=0027",
        "Defaults ignore_dot",
        "Defaults env_reset"
    ]

    r39_detected_elements = r39_data.get("detected_elements", [])

    # Sauvegarde du fichier sudoers si ce n'est pas encore fait
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    # Normalisation simple des directives détectées (enlevant tabs/spaces)
    normalized_detected = ['\t'.join(line.split()) for line in r39_detected_elements]

    for line in normalized_detected:
        if line not in directives_expected:
            escaped_line = line.replace(" ", "[[:space:]]*")
            sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
            execute_ssh_command(serveur, sed_command)

    print("-  R39 : Directives sudoers non conformes commentées avec succès.")
    update_report('moyen', 'access_management', 'R39')


##l'application se fait bien mais l'analyse donne false
"""

L'application de la règle R40 vise à restreindre l'accès sudo aux seuls utilisateurs autorisés, tels que root, ubuntu, administrateur, et %admin, tout en conservant les privilèges spécifiques pour d'autres utilisateurs ayant des restrictions sur certaines commandes. Si un utilisateur non autorisé dispose de privilèges sudo complets (ALL), ces privilèges sont révoqués. En revanche, si un utilisateur possède des restrictions spécifiques (par exemple, l'accès à /usr/bin/apt), sa configuration est préservée. Le fichier /etc/sudoers est modifié en conséquence, et un rapport est mis à jour pour refléter l'état de la conformité.

"""

def apply_R40(serveur, report):

    r40_data = report.get("R40", {})
    if not r40_data.get("apply", False):
        print("-  R40 : Aucune action nécessaire.")
        return "Compliant"

    r40_detected_elements = r40_data.get("detected_elements", [])

    # Sauvegarde du fichier sudoers avant modification si ce n'est pas encore fait
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r40_detected_elements:
        # Préparer la ligne pour la recherche flexible dans sudoers (tabulations/espaces)
        escaped_line = line.replace(" ", "[[:space:]]*")
        sed_command = f"sudo sed -i 's|^[[:space:]]*{escaped_line}$|# &|' /etc/sudoers"
        execute_ssh_command(serveur, sed_command)

    print("-  R40 : Les entrées sudo non privilégiées ont été commentées avec succès.")
    update_report('moyen', 'access_management', 'R40')

#Regle 42
def apply_R42(serveur, report):
    r42_data = report.get("R42", {})

    if not r42_data.get("apply", False):
        print("-  R42 : Aucune action nécessaire.")
        return "Compliant"

    r42_detected_elements = r42_data.get("detected_elements", [])

    if not r42_detected_elements:
        print("-  R42 : Aucun opérateur de négation détecté.")
        update_report('min', 'access_management', 'R42')
        return "Compliant"

    # Sauvegarde du fichier sudoers avant modification si ce n'est pas encore fait
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r42_detected_elements:
        escaped_line = line.replace(" ", "[[:space:]]*")
        sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
        execute_ssh_command(serveur, sed_command)

    print("-  R42 : Les lignes contenant des opérateurs de négation ont été commentées avec succès.")
    update_report('moyen', 'access_management', 'R42')

def apply_R43(serveur, report):

    r43_data = report.get("R43", {})

    if not r43_data.get("apply", False):
        print("-  R43 : Aucune action nécessaire.")
        return "Compliant"

    r43_detected_elements = r43_data.get("detected_elements", [])

    # Sauvegarde du fichier sudoers avant modification si ce n'est pas encore fait
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r43_detected_elements:
        if not line.startswith("#"):
            escaped_line = line.replace(" ", "[[:space:]]*")
            sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
            execute_ssh_command(serveur, sed_command)

    print("-  R43 : Les lignes sudo sans spécification stricte d’arguments ont été commentées avec succès.")
    update_report('moyen', 'access_management', 'R43')


def apply_R44(serveur, report):

    r44_data = report.get("R44", {})

    if not r44_data.get("apply", False):
        print("-  R44 : Aucune action nécessaire.")
        return "Compliant"

    r44_detected_elements = r44_data.get("detected_elements", {}).get("sudoedit_usage", [])
    
    # Sauvegarde du fichier sudoers avant modification si ce n'est pas encore fait
    execute_ssh_command(serveur, "sudo cp -n /etc/sudoers /etc/sudoers.htms")

    for line in r44_detected_elements:
        if not line.startswith("#"):
            escaped_line = line.replace(" ", "[[:space:]]*")
            sed_command = f"sudo sed -i 's|^{escaped_line}$|# &|' /etc/sudoers"
            execute_ssh_command(serveur, sed_command)

    print("-  R44 : Les lignes avec des violations de configuration pour sudoedit ont été commentées avec succès.")
    update_report('moyen', 'access_management', 'R44')


def apply_R50(serveur, report):

    """Applique la règle R50 en vérifiant et modifiant les permissions des fichiers sensibles."""
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
        print("-  R50 : Aucune action nécessaire.")
        return "Compliant"
      
    print("\n    Appling rule 50 (Restrict access permissions to sensitive files and directories)    \n")
    
    # Recuperation of the elements detected
    detected_elements = r50_data.get("detected_elements", [])

    if not detected_elements:            
        print("Rule 50 : Nothing elements are detected for insecure file editing")
        return

    # Liste des fichiers modifiés
    all_files_modified = []

    # Application des permissions attendues
    for file_path in detected_elements:

        file_name = file_path.split(" ")[2]

        if file_name in expected_permissions:
            
            # Modifier les permissions
            chmod_command = f"sudo chmod {expected_permissions[file_name]} {file_name}"
            serveur.exec_command(chmod_command)
            all_files_modified.append(file_path)

    update_report('moyen', 'access_management', 'R50') 


#Regle 52
def apply_R52(serveur, report):
    """Applique la règle R52 en vérifiant et modifiant les permissions des sockets et tubes nommés."""
    print("\n  Application of rule 52 (Protect named pipes and sockets)    \n")

    r52_data = report.get("R52", {})
    #Recuperation of the expected permissions from the reference data
    expected_permissions = {

    entry.rsplit(" ", 1)[0]: entry.rsplit(" ", 1)[1]
    for entry in r52_data.get("expected_elements", [])

    }

    if not r52_data.get("apply", False):
        print("-  R52 : Aucune action nécessaire.")
        return "Compliant"
    
    # Détection des éléments existants dans le rapport
    detected_elements = r52_data.get("differences", [])

    if not detected_elements:
        print("Rule 52 : Nothing elements are detected for changing permission")
        return

    # Liste des éléments modifiés
    all_elements_modified = []

    # Application des permissions attendues
    for element in detected_elements:
        file_path = element.split()[0]
        if file_path in expected_permissions:
            # Modifier les permissions
            chmod_command = f"sudo chmod {expected_permissions[file_path]} {file_path}"
            serveur.exec_command(chmod_command)
            all_elements_modified.append(file_path)

    update_report('moyen', 'access_management', 'R52') 
    print("The R52 is ssuccessfully applied and  report updated")
    
#Regle 55
def apply_R55(serveur, report):
    """
    Applique la règle R55 : Isolation des répertoires temporaires des utilisateurs.
    - Vérifie si apply est True
    - Sauvegarde les répertoires détectés
    - Monte les répertoires avec les options de sécurité
    """
    # Vérification si la règle est activée
    if  report.get("access_management", {}).get("R55", {}).get("apply", True): 
        # Récupérer la règle R55 depuis le rapport
        detected_elements = report.get("access_management", {}).get("R55", {}).get("detected_elements", [])
        # Vérification si des éléments ont été détectés
        if not detected_elements:
            print("   Rule 55 : Nothing elements are detected, for isolation.")
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

        print("-  The R55 is ssuccessfully applied and  report updated 📁")


#Regle 67
def apply_R67(serveur, report, reference_data):
    """
    
    Affiche les règles PAM détectées (R67) et les règles manquantes avec risques et commandes associées.
    
    """

    # Vérification si la règle est activée
    if report.get("access_management", {}).get("R67", {}).get("apply", True):      
        print("\n    Appling rule 67 (PAM authentication))    \n")  
        detected_elements = report.get("access_management", {}).get("R67", {}).get("detected_elements", [])
        if not detected_elements:
            print("   Nothing PAM rule are detected for PAM authentication .")
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

        # Etape 2 : Affichage des éléments attendus non détectés
        expected_elements = reference_data.get("R67", {}).get("expected", {}).get("pam_rules", [])

        for pam_rule in expected_elements:
            if pam_rule not in detected_elements:
                # Identifie le type de la règle pour la répartition dans le bon fichier
                rule_type = "auth" if "auth" in pam_rule else "session" if "session" in pam_rule else "account" if "account" in pam_rule else "password"
                pam_file = pam_files.get(rule_type)

                # Si le fichier est trouvé, on affiche la commande d'application
                if pam_file:
                    print(f"\nDirective PAM:  {pam_rule}")
                    print(f"\nRisque : {risks.get(pam_rule, 'Risque non documenté.')}")
                    print(f"\nCommande d'application : echo '{pam_rule}' | sudo tee -a {pam_file} > /dev/null")
                    print("\n" + "+" * 100)


def apply_access_management(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("access_management",None)
    if  apply_data is None: 
        return 
    
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
            "R52": (apply_R52, "Ensure named pipes and sockets have restricted permissions"),
            "R55": (apply_R55, "Isolate user temporary directories"),
            "R67": (apply_R67, "Ensure remote authentication via PAM")
        },
        "avancé": {
            # À compléter si besoin
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id,None): 
                print(f"-> Application de la règle {rule_id} : {comment}")
                function(serveur , apply_data)

    print(f"\n-  Correctifs appliqués - GESTION ACCÈS - Niveau {niveau.upper()}")
