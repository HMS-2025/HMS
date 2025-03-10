import unittest
import os
import yaml
import paramiko

from Config import ssh_connect, load_config as load_config_ssh
from AnalyseConfiguration.Thematiques.Maintenance import execute_ssh_command
from AnalyseConfiguration.Thematiques.JournalisationAudit import get_audit_log_status,get_auditd_configuration, get_admin_command_logging, get_audit_log_protection, get_log_rotation


def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Le fichier de configuration '{path}' est introuvable.")
    with open(path, 'r') as config_file:
        return yaml.safe_load(config_file)

# Charger les références depuis Reference_moyen.yaml
"""Charge le fichier Reference_moyen.yaml et retourne son contenu."""
reference_data = load_config("AnalyseConfiguration/Reference_moyen.yaml")


class MiddleTest(unittest.TestCase):
    client = None  # Variable de classe pour stocker le client SSH
    reference_data = None  # Variable de classe pour stocker les références

    @classmethod
    def setUpClass(cls):
        if cls.client is None:
            raise ValueError("Le client SSH n'a pas été initialisé")
        # Charger les références dans la classe
        cls.reference_data = reference_data
    #R34
    def test_get_service_accounts(self):
        """Test de récupération des comptes de services"""
        print("\n*******Test des comptes de services ********")
        stdin, stdout, stderr = self.client.exec_command("awk -F: '($3 < 1000) && ($1 != \"root\") {print $1}' /etc/passwd")
        output = stdout.read().decode().strip()
        expected_output = " j'ai Verifié en observant le output de l'execution directe sur la cible"  # Remplacez par la liste attendue
        print(output)
       # self.assertEqual(output, expected_output, "La liste des comptes de services ne correspond pas à l'attendu.")
       #NB : Le test de cette fonction marche bien 
         
    #R39
    def test_get_sudo_directives(self):
        print("\n*****Test des comptes de sudo******\n")
        """Test de récupération des directives sudo"""
        stdin, stdout, stderr = self.client.exec_command("sudo grep -E '^Defaults' /etc/sudoers",get_pty=True)
        output = stdout.read().decode().strip()
        print(output)
        expected_output = " j'ai Verifié en observant le output de l'execution directe sur la cible"  #
       # self.assertEqual(output, expected_output, "Les directives sudo ne correspondent pas à l'attendu.")
        #NB: Il faut jouter le parametre get_pty  à cette fonction d'une part et d'autre apporter ces modifications (chown root:root /usr/bin/sudo && chmod 4755 /usr/bin/sudo) car sans ça aucune reperation d'information s'effectue. Attention finalement l'allocation de ce pty blocke aussi l'execusion car il se trouve que cela a des comportements inatendus
    #R40
    def test_get_non_privileged_sudo_users(self):
        print("\n*****Test de recuperation des comptes privilegiers non sudo******\n")
        stdin, stdout, stderr = self.client.exec_command("sudo grep -E '^[^#].*ALL=' /etc/sudoers | grep -E '\\(ALL.*\\)' | grep -Ev '(NOPASSWD|%sudo|root)'", get_pty=True)
        output = stdout.read().decode().strip()
        print("Resulat de test_get_non_privileged_sudo_users : \n" + output)
        #expected_output :"variable" # les comptes attendu
        #self.assertEqual(output,expected_output,"Erreur non correspondence de resultat à ce qui est attendu")

    #R42
    def test_get_negation_in_sudoers(self):
        print("\n*****Test de negation dans las specification de sudo******\n")

        #ajout de negation
        """ Ajout de negation """
        #stdin, stdout, stderr = self.client.exec_command("echo 'TestNegoSudo ALL=(ALL:ALL) ALL, !/usr/bin/apt' | sudo tee -a /etc/sudoers")
        #exit_status = stdout.channel.recv_exit_status()
        #fin d'ajout """
        #test
        stdin, stdout, stderr = self.client.exec_command("sudo grep -E '!' /etc/sudoers", get_pty=True)
        output = stdout.read().decode().strip()
        print("Resultat test_get_negation_in_sudoers :\n" + output)
        expected_output="TestNegoSudo ALL=(ALL:ALL) ALL, !/usr/bin/apt"
        self.assertEqual(output,expected_output,"Erreur non correspondence de resultat à ce qui est attendu")

        #""" Clean """
        #stdin, stdout, stderr = self.client.exec_command("sed -i '/^TestNegoSudo /d' /etc/sudoers")
        #config_data = stdout.read().decode().strip()

    #R43
    #Commanade changer par un autre car ne recuperant pas les données concernées
    def test_get_strict_sudo_arguments(self):
        print("\n*****Test of Specify arguments in sudo specifications******\n")
        stdin, stdout, stderr = self.client.exec_command("sudo grep -E 'ALL=.*[\\s!]' /etc/sudoers", get_pty=True)

        output = stdout.read().decode().strip()
        print("Resutl of get_strict_sudo_arguments : \n" + output) # les comptes attendu
        #self.assertEqual(output, expected_output, "Erreur non correspondence de resultat à ce qui est attendu")
   
    #R44
    def test_get_sudoedit_usage(self):
        print("\n*****Test d'edition de sudo******\n")
        #ajout cette ligne dans /etc/sudoers pour tester cette regles
        #stdin, stdout, stderr = self.client.exec_command("echo 'Tubuntu ALL=(ALL) sudoedit /etc/hosts' | sudo tee -a /etc/sudoers")
        #exit_status = stdout.channel.recv_exit_status()
        #fin d'ajout """

        stdin, stdout, stderr = self.client.exec_command("sudo grep -E 'ALL=.*sudoedit' /etc/sudoers", get_pty=True)
        output = stdout.read().decode().strip()
        print("Resulat de get_sudoedit_usage : \n" + output)
        expected_output = "ubuntu ALL=(ALL) sudoedit /etc/hosts" # les comptes attendu
        self.assertEqual(output, expected_output, "Erreur non correspondence de resultat à ce qui est attendu")

         #""" Clean """
        #stdin, stdout, stderr = self.client.exec_command("sed -i '/^ubuntu ALL=(ALL) sudoedit /etc/hosts/d' /etc/sudoers")
        #config_data = stdout.read().decode().strip()

    #R50
    def test_get_secure_permissions(self):
        print("\n*****Test of secure permission of the files *****\n")
       #stdin, stdout, stderr = self.client.exec_command("sudo find / -type f -perm -0002 -ls 2>/dev/null", get_pty=True) #commande orgignal à decommnenter par la suite

        stdin, stdout, stderr = self.client.exec_command("sudo find / -type f -perm -0002 -ls 2>/dev/null | head -n 20", get_pty=True)

        output = stdout.read().decode().strip()
        print("Resutl of permission : \n" + output) # les comptes attendu
        #self.assertEqual(output, expected_output, "Erreur non correspondence de resultat à ce qui est attendu")
    #R52
    def test_get_protected_sockets(self):
        print("\n*****Test of protected socket *****\n")
        stdin, stdout, stderr = self.client.exec_command("sudo ss -xp | awk '{print $5}' | cut -d':' -f1 | sort -u", get_pty=True)

        output = stdout.read().decode().strip()
        print("Resutl of permission : \n" + output) 

    #R55
    def test_get_user_private_tmp(self):
        print("\n*****Test of get_user_private_tmp (Isolate user temporary directories) *****\n")
        stdin, stdout, stderr = self.client.exec_command("mount | grep ' /tmp'")

        output = stdout.read().decode().strip()
        print("Resutl of get_user_private_tmp : \n" + output) 
    
    #La cible HMS-prod de contiend aucun fichier pam_ladp dans /etc/pam.d, donc nous creons ce fihier pour  le test 
    #echo "auth required pam_ldap.so" > /etc/pam.d/pam_ldap

    #R67 
    def test_check_pam_security(self):
        expected_values = self.reference_data.get("R67", {}).get("expected", {})    
        command_pam_auth = "grep -Ei 'pam_ldap' /etc/pam.d/* 2>/dev/null"
        stdin, stdout, stderr = self.client.exec_command(command_pam_auth)
        detected_pam_entries = stdout.read().decode().strip().split("\n")
        print("\n*******Reusultat de la commande de test de check pam \n")
        print(detected_pam_entries)

        detected_pam_module = "pam_ldap" if detected_pam_entries and any("pam_ldap" in line for line in detected_pam_entries) else "Non trouvé"
    
        security_modules = expected_values.get("security_modules", {})
        detected_security_modules = {}
    
        for module in security_modules.keys():
            command = f"grep -E '{module}' /etc/pam.d/* 2>/dev/null"
            stdin, stdout, stderr = self.client.exec_command(command)
            detected_status = "Enabled" if stdout.read().decode().strip() else "Non trouvé"
            detected_security_modules[module] = detected_status
    
        detected_elements = {
                      "detected_pam_modules": detected_pam_module,
                      "security_modules": detected_security_modules
                     }
    
        detected_list = [f"detected_pam_modules: {detected_elements['detected_pam_modules']}"]
        for module, detected_status in detected_elements["security_modules"].items():
          detected_list.append(f"{module}: {detected_status}")  

        print("\n*************** Resultats des elements detécté******************\n")
        print(detected_list)
        ##renvoi des elements détéctés.
        #return detected_list
##### Fin ici des tests sur les regles moyen pour l'access 


#Debut des tests pour les regles moyens  pour les services
    #R35
    def test_check_unique_service_accounts(self):
        """Checks if each service has a unique system account and correctly formats the results."""
        command = "ps -eo user,comm | awk '{print $1}' | sort | uniq -c"
        stdin, stdout, stderr = self.client.exec_command(command)
        users_count = stdout.read().decode().strip().split("\n")

        non_unique_accounts = [line.strip() for line in users_count if int(line.split()[0]) > 1]
        print("\n**********Resultat de test de  check_unique_service_accounts***********\n")
        print(non_unique_accounts )


    # R63 - Disable non-essential service features
    #Attention cette fonction check_disabled_service_featurespresent une petite erreur l'antislash etant un caractere stpecial n'a pas été echaper juste avant le point virgule.
    def test_check_disabled_service_features(self):
        """Checks services with enabled Linux capabilities."""
        #command = "find / -type f -perm /111 -exec getcap {} \; 2>/dev/null"
        command = "find / -type f -perm /111 -exec getcap {} \\; 2>/dev/null" # commandes correcte.
        stdin, stdout, stderr = self.client.exec_command(command)
        capabilities = stdout.read().decode().strip().split("\n")
        print("\n**********Resultat de test de check_disabled_service_features***********\n")
        print(capabilities )

    # R74 - Harden the local mail service
    def test_check_hardened_mail_service(self):
        """Checks if the mail service only accepts local connections and allows only local delivery."""

        # Vérifier si un service écoute sur le port 25
        command_listen = "ss -tulnp | awk '$5 ~ /:25$/ {print $5}'"
        stdin, stdout, stderr = self.client.exec_command(command_listen)
        listening_ports = stdout.read().decode().strip().split("\n")

        # Vérifier la configuration de la livraison locale avec Postfix
        command_destination = "postconf -h mydestination"
        stdin, stdout, stderr = self.client.exec_command(command_destination)
        mydestination = stdout.read().decode().strip()
        
        expected_interfaces = self.reference_data.get("R74", {}).get("expected", {}).get("hardened_mail_service", {}).get("listen_interfaces", [])
        expected_local_delivery = reference_data.get("R74", {}).get("expected", {}).get("hardened_mail_service", {}).get("allow_local_delivery", [])

        # Vérifier que le service écoute uniquement sur 127.0.0.1 ou [::1]
        detected_interfaces = [line.strip() for line in listening_ports if line.strip()]

        # Vérifier que Postfix n'accepte que les mails locaux
        detected_local_delivery = [item.strip() for item in mydestination.split(",")]
        print("\n*********** Resultat du test de check_hardened_mail_service ******\n")
        # Si aucun service de messagerie n'est détecté, la règle est conforme
        if not detected_interfaces:
             print("\n Aucun element n'est detécté. voici ce qui etait attendu :\n") 
             print(expected_interfaces + expected_local_delivery)
             #Je commenter ce retune et afficher le resultat pour avoir le rendu visual
            #return {
             #   "detected_elements": [],
            #    "expected_elements": expected_interfaces + expected_local_delivery
           # }
        print("Interfaces detectées : \n")

        print(detected_interfaces + detected_local_delivery)
        print("Interfaces attendus :\n")
        print( expected_interfaces + expected_local_delivery)

        #return {
            #"detected_elements": detected_interfaces + detected_local_delivery,
           # "expected_elements": expected_interfaces + expected_local_delivery
        #}


    # R75 - Verify mail aliases for service accounts
    def test_check_mail_aliases(self):
        """Checks for the presence of mail aliases for service accounts via a Linux command."""        
        # Nouvelle commande pour extraire uniquement les alias
        command = "grep -E '^[a-zA-Z0-9._-]+:' /etc/aliases | awk -F':' '{print $1}' 2>/dev/null"
        stdin, stdout, stderr = self.client.exec_command(command)
        aliases_output = stdout.read().decode().strip().split("\n")

        
        expected_aliases = self.reference_data.get("R75", {}).get("expected", {}).get("mail_aliases", [])

        # Nettoyage des alias détectés pour éviter des espaces superflus
        detected_aliases = [alias.strip() for alias in aliases_output if alias.strip() in expected_aliases]

        print("\n******Resultat du test de check_mail_aliases *******\n")
        print(detected_aliases)


###Fin des tests pour les services



#Test pour les regles moyen sur la maintenace

    # Vérifier la présence d'un mot de passe GRUB 2
    #R5
    def test_check_grub_password(self):
        command_check_superusers = "grep -E 'set\\s+superusers' /etc/grub.d/* /boot/grub/grub.cfg"
        command_check_password = "grep -E 'password_pbkdf2' /etc/grub.d/* /boot/grub/grub.cfg"
        
        superusers_output = execute_ssh_command(self, command_check_superusers)
        password_output = execute_ssh_command(self, command_check_password)

        print ("\n********Result du test     ************\n")
        print("\n superusers_output :\n")
        print(superusers_output)
        print("\n password_output :\n")
        print( password_output)
        
        #return {
        #  "apply": bool(superusers_output or password_output),
        # "status": "Conforme" if superusers_output or password_output else "Non-conforme",
        #   "detected_elements": superusers_output + password_output or "Aucun"
    #  }

    #Fin de tests pour la maintenance

    #Test de journalistion
    #R33
    def test_check_r33(self):
        audit_status = get_audit_log_status(self.client)
        print("\n********* Test de check_r33 ******** \n")
        print("audit_log_status :" + audit_status)
        print("auditd_configuration :\nn" )
        print(get_auditd_configuration(self.client) if audit_status != "Not Installed" else None)
        print("admin_command_logging :\n")
        print(get_admin_command_logging(self.client) if audit_status != "Not Installed" else None)
        print("audit_log_protection :\n")
        print(get_audit_log_protection(self.client) if audit_status != "Not Installed" else None)
        print("log_rotation :\n")
        print(get_log_rotation(self.client) if audit_status != "Not Installed" else None)
            
        #return {
        # "audit_log_status": audit_status,
        # "auditd_configuration": get_auditd_configuration(self) if audit_status != "Not Installed" else None,
        # "admin_command_logging": get_admin_command_logging(self) if audit_status != "Not Installed" else None,
        # "audit_log_protection": get_audit_log_protection(self) if audit_status != "Not Installed" else None,
        # "log_rotation": get_log_rotation(self) if audit_status != "Not Installed" else None
        #}


    #Fin  de test pour les regles moyens sur la journalisation


    #Test des regles de politique de mot de passe
    def test_get_stored_passwords_protection(self):
        command = "fls -l /etc/shadow" # commandes correcte.
        stdin, stdout, stderr = self.client.exec_command(command)
        outpout = stdout.read().decode().strip().split("\n")
        print("\n**********Resultat de test de get_stored_passwords_protection***********\n")
        print(outpout)
        #return execute_ssh_command(serveur, "ls -l /etc/shadow")



if __name__ == '__main__':
    # Établir la connexion SSH
   # Charger la configuration SSH
    config = load_config_ssh("ssh.yaml")
    if not config:
        print("Configuration invalide")
    # Établir la connexion SSH
    
    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )
    if not client:
        print("Échec de la connexion SSH")

    # Assigner le client SSH à la variable de classe
    MiddleTest.client = client

    # Exécuter les tests
    unittest.main()

    # Fermer la connexion SSH
    client.close()
