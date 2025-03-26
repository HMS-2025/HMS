import unittest
import os
import yaml
import paramiko

from Config import ssh_connect, load_config as load_config_ssh
from AnalyseConfiguration.Analyseur import analyse_moyen
from AnalyseConfiguration.Thematiques.Maintenance import execute_ssh_command
from AnalyseConfiguration.Thematiques.JournalisationAudit import get_audit_log_status,get_auditd_configuration, get_admin_command_logging, get_audit_log_protection, get_log_rotation


def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Le fichier de configuration '{path}' est introuvable.")
    with open(path, 'r') as config_file:
        return yaml.safe_load(config_file)

# Charger les références depuis Reference_moyen.yaml
"""Charge le fichier Reference_moyen.yaml et retourne son contenu."""
   
class MiddleAnalysisTest(unittest.TestCase):
    def __init__(self, client, methodName="run_tests"):
        super().__init__(methodName)
        self.client = client
        self.reference_data=reference_data
   
   #R34
    def test_get_service_accounts(self):
        """Test de récupération des comptes de services"""
        print("\n*******Test des comptes de services ********")
        #Insertion de compte service active pour le test        
        #stdin, stdout, stderr=self.client.exec_command("sudo useradd -m -s /bin/false testmysql && sudo passwd -d testmysql")
        #Activation du compte mysql pour le test
        stdin, stdout, stderr=self.client.exec_command("sudo passwd -u mysql && sudo usermod -p $(openssl passwd -1 \"mysql\") mysql && sudo usermod -s /bin/bash mysql")

        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("mysql", result["access_management"]["R34"]["detected_elements"])        
      
       #Desactiver sudo passwd -l mysql && sudo usermod -s /usr/sbin/False mysql
        stdin, stdout, stderr=self.client.exec_command("sudo passwd -l mysql && sudo usermod -s /usr/sbin/False mysql")
        exit_status = stdout.channel.recv_exit_status()
        #Apres descativation de ce compte, nous relancons le test pour s'assurer que ce compte n'est plus detecter comme étant active 
         #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("mysql", result["access_management"]["R34"]["detected_elements"])     
    
   # R39
    def test_get_sudo_directives(self):
        print("\n*****Test des comptes de sudo******\n")
        """Test de récupération des directives sudo"""
       
         #Ajout de directive pour le test
        stdin, stdout, stderr=self.client.exec_command("sudo echo \"Defaults\tenv_keep\t+=\t\"R39\"\" | sudo tee -a /etc/sudoers")
        

        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("Defaults\tenv_keep\t+=\tR39", result["access_management"]["R39"]["detected_elements"])

        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^Defaults\tenv_keep\t+=\tR39/d' /etc/sudoers")
        #Retest
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("Defaults\tenv_keep\t+=\tR39", result["access_management"]["R39"]["detected_elements"])  



    #Test Regle 40
    def get_non_privileged_sudo_users(self):
        print("\n*****Test de recuperation des comptes privilegiers non sudo******\n")
        stdin, stdout, stderr = self.client.exec_command("sudo echo \"TestR40 ALL=(ALL) ALL\" | sudo tee -a /etc/sudoers")
        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("TestR40 ALL=(ALL) ALL", result["access_management"]["R40"]["detected_elements"])  
        
        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^TestR40/d' /etc/sudoers")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("TestR40 ALL=(ALL) ALL", result["access_management"]["R40"]["detected_elements"])  

    #R42
    def test_get_negation_in_sudoers(self):
        print("\n*****Test de negation dans las specification de sudo******\n")

        #ajout de negation
        """ Ajout de negation """
        stdin, stdout, stderr = self.client.exec_command("echo 'TestR42 ALL=(ALL:ALL) ALL, !/usr/bin/apt' | sudo tee -a /etc/sudoers")
        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("TestR42 ALL=(ALL:ALL) ALL, !/usr/bin/apt", result["access_management"]["R42"]["detected_elements"])  
        
        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^TestR42/d' /etc/sudoers")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("TestR42 ALL=(ALL:ALL) ALL, !/usr/bin/apt", result["access_management"]["R42"]["detected_elements"])  

    #Regle 43
    #Commanade changer par un autre car ne recuperant pas les données concernées
    def test_get_strict_sudo_arguments(self):
        print("\n*****Test of Specify arguments in sudo specifications******\n")
        #ajout de negation
        """ Ajout de data de test """
        stdin, stdout, stderr = self.client.exec_command("echo 'TestR43 ALL=(ALL) sudoedit /etc/hosts'| sudo tee -a /etc/sudoers")
        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("TestR43 ALL=(ALL) sudoedit /etc/hosts", result["access_management"]["R43"]["detected_elements"])  
        
        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^TestR43/d' /etc/sudoers")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("TestR43 ALL=(ALL) sudoedit /etc/hosts", result["access_management"]["R43"]["detected_elements"])  

    #Regle R44
    def test_get_sudoedit_usage(self):
        print("\n*****Test d'edition de sudo******\n")
       
        stdin, stdout, stderr = self.client.exec_command("echo 'TestR44 ALL=(ALL)  /etc/bin/nano /etc/hosts' | sudo tee -a /etc/sudoers")
        exit_status = stdout.channel.recv_exit_status()

        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("TestR44 ALL=(ALL)  /etc/bin/nano /etc/hosts", result["access_management"]["R44"]["detected_elements"])  
        
        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^TestR44/d' /etc/sudoers")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("TestR44 ALL=(ALL)  /etc/bin/nano /etc/hosts", result["access_management"]["R44"]["detected_elements"])  

    #Regle 50
    def test_get_secure_permissions(self):
        print("\n*****Test of secure permission of the files *****\n")
        stdin, stdout, stderr = self.client.exec_command("sudo cp /etc/gshadow /etc/gshadow.htms && sudo chmod 777 /etc/gshadow")
        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertTrue(any("/etc/gshadow" in item for item in result["access_management"]["R50"]["detected_elements"]))
        
        #Repprise de permission orignales
        stdin, stdout, stderr = self.client.exec_command("sudo mv /etc/gshadow.htms /etc/gshadow")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertFalse(any("/etc/gshadow" in item for item in result["access_management"]["R50"]["detected_elements"]))
 

      
      #Regle 52

    def test_get_protected_sockets(self):
        print("\n*****Test of protected socket *****\n")
        stdin, stdout, stderr = self.client.exec_command("sudo chmod 777  /run/systemd/notify")
        exit_status = stdout.channel.recv_exit_status()
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertTrue(any("/run/systemd/notify 777" in item for item in result["access_management"]["R52"]["detected_elements"]))
        
        #Repprise de permission orignales
        stdin, stdout, stderr = self.client.exec_command("sudo chmod 750  /run/systemd/notify")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertTrue(any("/run/systemd/notify 750" in item for item in result["access_management"]["R52"]["detected_elements"]))
       
    

    #Regle 55 
    def test_get_user_private_tmp(self):
        print("\n*****Test of get_user_private_tmp (Isolate user temporary directories) *****\n")
        stdin, stdout, stderr = self.client.exec_command("echo \"session optional pam_mktemp.so\" | sudo tee -a /etc/pam.d/login")
        exit_status = stdout.channel.recv_exit_status()

        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("session optional pam_mktemp.so", result["access_management"]["R55"]["detected_elements"])  
        
        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^session optional pam_mktemp.so/d' /etc/pam.d/login")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("session optional pam_mktemp.so", result["access_management"]["R55"]["detected_elements"])  



 #######    Partie reseau    ##########
    #Regle 67
    def test_check_pam_security(self):
        print("\n******* Test du check pam security   *********************\n")        
        stdin, stdout, stderr = self.client.exec_command("echo \"account sufficient pam_ldap.so\" | sudo tee -a /etc/pam.d/sshd")
        exit_status = stdout.channel.recv_exit_status()

        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertIn("account sufficient pam_ldap.so", result["network"]["R67"]["detected_elements"]["pam_rules"])  
        
        #Suppression
        stdin, stdout, stderr = self.client.exec_command("sudo sed -i '/^account sufficient pam_ldap.so/d' /etc/pam.d/sshd")
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertNotIn("account sufficient pam_ldap.so", result["network"]["R67"]["detected_elements"]["pam_rules"])  


    #Debut des tests pour les regles moyens  pour les services
    #R35
    def test_check_unique_service_accounts(self):
        print("\n********** Test de  check_unique_service_accounts***********\n")
        #verifier  si www-data est unique
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertTrue(any("www-data" in item for item in result["services"]["R35"]["detected_elements"]))

        
    # R63 - Disable non-essential service features
    #Attention cette fonction check_disabled_service_featurespresent une petite erreur l'antislash etant un caractere stpecial n'a pas été echaper juste avant le point virgule.
    def test_check_disabled_service_features(self):
        """Checks services with enabled Linux capabilities."""
        print("\n**********Resultat de test de check_disabled_service_features***********\n")
        #verifier la destection de /usr/bin/ping = cap_net_raw+ep qui est present
        #Test
        analyse_moyen(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_moyen.yml")
        self.assertTrue(any("/usr/bin/ping = cap_net_raw+ep" in item for item in result["services"]["R63"]["detected_elements"]))


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
        
        superusers_output = self.client.exec_command(command_check_superusers)
        password_output = self.client.exec_command(command_check_password)

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




    def run_tests(self):
        """Exécuter les tests"""
        suite = unittest.TestSuite()
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_service_accounts"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_sudo_directives"))
        suite.addTest(MiddleAnalysisTest(self.client,"get_non_privileged_sudo_users"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_negation_in_sudoers"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_strict_sudo_arguments"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_strict_sudo_arguments"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_secure_permissions"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_protected_sockets"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_user_private_tmp"))
        suite.addTest(MiddleAnalysisTest(self.client,"test_check_pam_security"))   
        suite.addTest(MiddleAnalysisTest(self.client,"test_check_unique_service_accounts"))         
        suite.addTest(MiddleAnalysisTest(self.client,"test_check_hardened_mail_service")) 
        suite.addTest(MiddleAnalysisTest(self.client,"test_check_mail_aliases")) 
        suite.addTest(MiddleAnalysisTest(self.client,"test_check_grub_password")) 
        suite.addTest(MiddleAnalysisTest(self.client,"test_check_r33")) 
        suite.addTest(MiddleAnalysisTest(self.client,"test_get_stored_passwords_protection"))
        
            
        # Exécution des tests
        runner = unittest.TextTestRunner()
        runner.run(suite)


# Création d'une suite de tests et ajout progressif
if __name__ == "__main__":
    #chargement des donnees de reference
    reference_data = load_config("AnalyseConfiguration/Reference_moyen.yaml")
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

   # Lancer les tests
    test_runner = MiddleAnalysisTest(client)
    test_runner.run_tests()

    # Fermer la connexion SSH
    client.close()
   






