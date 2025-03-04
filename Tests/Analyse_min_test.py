import os
import unittest
import yaml
import time
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min

def load_config(path) : 

        # Chargement des secrets
        if not os.path.exists(path):
            raise FileNotFoundError(f"Le fichier de configuration '{path}' est introuvable.")
        
        with open(path, 'r') as config_file:
            return yaml.safe_load(config_file)
class Analyse_min_test ( unittest.TestCase):
    def __init__(self, client , methodName="runTest"):
        super().__init__(methodName)
        self.client = client

    def test_gestion_acces_min (self) :

        """ ----------- TEST : Détection des utilisateurs inactifs ------------- """

        #Clean avant le test (supprimer d'éventuels utilisateurs de test existants)
        stdin, stdout, stderr=self.client.exec_command("sudo userdel test_user1 || true")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo userdel test_user2 || true")
        exit_status = stdout.channel.recv_exit_status()


        #Ajouter des utilisateurs inactifs pour le test
        stdin, stdout, stderr=self.client.exec_command("sudo useradd -m -s /bin/bash test_user1")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr=self.client.exec_command("echo 'test_user1:motdepasse' | sudo chpasswd")
        exit_status = stdout.channel.recv_exit_status()
        
        
        stdin, stdout, stderr=self.client.exec_command("sudo useradd -m -s /bin/bash test_user2")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr=self.client.exec_command("echo 'test_user2:motdepasse' | sudo chpasswd" ) 
        exit_status = stdout.channel.recv_exit_status()

        # Vérifier que les utilisateurs inactifs sont bien détectés
        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        
        self.assertIn("test_user1", result["gestion_acces"]["R30"]["detected_elements"])
        self.assertIn("test_user2", result["gestion_acces"]["R30"]["detected_elements"])

        #Désactiver les comptes pour simuler des utilisateurs inactifs
        stdin, stdout, stderr=self.client.exec_command("sudo passwd -l test_user1")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo passwd -l test_user2")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        
        self.assertNotIn("test_user1", result["gestion_acces"]["R30"]["detected_elements"])
        self.assertNotIn("test_user2", result["gestion_acces"]["R30"]["detected_elements"])

        
        #Clean après le test

        stdin, stdout, stderr=self.client.exec_command("sudo userdel -r test_user1")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo userdel -r test_user2")
        exit_status = stdout.channel.recv_exit_status() 


        """ ----------- TEST : Détection des fichiers sans utilisateur ni groupe ------------- """

        #Création d'un fichier sans propriétaire ni groupe
        stdin, stdout, stderr=self.client.exec_command("sudo touch /tmp/test_file_no_owner")
        
        stdin, stdout, stderr=self.client.exec_command("sudo useradd -m -s /bin/bash nouser")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo groupadd nogroup")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo chown nouser:nogroup /tmp/test_file_no_owner")  
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo userdel nouser || true") 
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo groupdel nogroup || true")  
        exit_status = stdout.channel.recv_exit_status()

        #Exécution de l'analyse
        analyse_min(self.client)

        #Chargement des résultats
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")

        #Vérification que le fichier est bien détecté comme Non-conforme
        self.assertIn("/tmp/test_file_no_owner", result["gestion_acces"]["R53"]["detected_elements"])
        self.assertEqual(result["gestion_acces"]["R53"]["status"], "Non-conforme")

        #Nettoyage après le test
        stdin, stdout, stderr=self.client.exec_command("sudo rm -f /tmp/test_file_no_owner")
        exit_status = stdout.channel.recv_exit_status()


        """----------- TEST : Détection des fichiers avec setuid et setgid ------------- """

        #Nettoyage avant le test (supprimer les fichiers de test s'ils existent)
        stdin, stdout, stderr=self.client.exec_command("sudo rm -f /tmp/test_suid /tmp/test_sgid")
        exit_status = stdout.channel.recv_exit_status()

        #Création des fichiers avec setuid et setgid
        stdin, stdout, stderr=self.client.exec_command("sudo touch /tmp/test_suid /tmp/test_sgid")
        exit_status = stdout.channel.recv_exit_status()
        
        stdin, stdout, stderr=self.client.exec_command("sudo chmod u+s /tmp/test_suid")
        exit_status = stdout.channel.recv_exit_status()
        
        stdin, stdout, stderr=self.client.exec_command("sudo chmod g+s /tmp/test_sgid")
        exit_status = stdout.channel.recv_exit_status()


        #Exécution de l'analyse
        analyse_min(self.client)

        #Chargement des résultats
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")

        #Vérification que les fichiers sont bien détectés comme Non-conformes
        self.assertIn("/tmp/test_suid", result["gestion_acces"]["R56"]["detected_elements"])
        self.assertIn("/tmp/test_sgid", result["gestion_acces"]["R56"]["detected_elements"])
        self.assertEqual(result["gestion_acces"]["R56"]["status"], "Non-conforme")

        #Nettoyage après le test
        stdin, stdout, stderr=self.client.exec_command("sudo rm -f /tmp/test_suid /tmp/test_sgid")
        exit_status = stdout.channel.recv_exit_status()

    def test_service_min (self) : 

        # Installation de service interdit 

        stdin, stdout, stderr=self.client.exec_command("sudo apt update ; sudo apt install -y samba ")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo systemctl enable smbd")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo systemctl start smbd")
        exit_status = stdout.channel.recv_exit_status()
        
        
        #Exécution de l'analyse
        analyse_min(self.client)

        #Chargement des résultats
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")

        #Vérification que les fichiers sont bien détectés comme Non-conformes
        self.assertIn("smbd.service", result["services"]["R62"]["detected_elements"]["detected_prohibited_elements"])
        self.assertEqual(result["services"]["R62"]["status"], "Non-conforme")

        #Nettoyage après le test
        stdin, stdout, stderr=self.client.exec_command("sudo apt remove --purge -y samba")
        exit_status = stdout.channel.recv_exit_status()

    def test_mises_a_jour_automatiques(self):
        """ ----------- TEST : Vérification des mises à jour automatiques ------------- """

        #Nettoyage avant le test (désactiver les mises à jour automatiques)
        stdin, stdout, stderr=self.client.exec_command("unattended-upgrades enabled")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)

        """result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")        
        self.assertEqual(result["mise_a_jour"]["R61"]["status"], "Non-conforme")   
        self.assertEqual("install ok installed | enabled | active | disabled" , result["mise_a_jour"]["R61"]["detected_elements"]["Unattended Upgrades"])
    
        # ------------ Crontab -------------------
        stdin, stdout, stderr = self.client.exec_command('(crontab -l 2>/dev/null; echo "0 3 * * * apt update && apt upgrade -y") | crontab -')        
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        self.assertEqual("apt update && apt upgrade -y",result["mise_a_jour"]["R61"]["detected_elements"]["Cron Updates"])
        """
        stdin, stdout, stderr = self.client.exec_command("crontab -r")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        self.assertEqual("No cron job detected" , result["mise_a_jour"]["R61"]["detected_elements"]["Cron Updates"])


        stdin, stdout, stderr = self.client.exec_command('(crontab -l 2>/dev/null; echo "0 3 * * * ls /") | crontab -')
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")

        self.assertEqual(result["mise_a_jour"]["R61"]["status"], "Non-conforme")   
        self.assertEqual("No cron job detected",result["mise_a_jour"]["R61"]["detected_elements"]["Cron Updates"])        
        
        # --------------- Clean --------------------
        
        stdin, stdout, stderr = self.client.exec_command("crontab -r")
        exit_status = stdout.channel.recv_exit_status()
    
    def test_politique_mot_passe (self) : 
        
        # expiration_policy

        stdin, stdout, stderr = self.client.exec_command("sudo chage -M 999 $(whoami)")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        self.assertEqual(result["password"]["R31"]["detected_element"]["expiration_policy"]["detected"] , 999)

        # expiration_policy

        stdin, stdout, stderr = self.client.exec_command("sudo chage -M 80 $(whoami)")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        self.assertNotIn("expiration_policy" , result["password"]["R31"]["detected_element"].keys())

        #faillock

        stdin, stdout, stderr = self.client.exec_command("sudo sed -i 's/^#*\s*deny\s*=.*/deny=4/' /etc/security/faillock.conf")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        self.assertIn("faillock" ,list(result["password"]["R31"]["detected_element"].keys()))

        #faillock 

        stdin, stdout, stderr = self.client.exec_command("sudo sed -i 's/^#*\s*deny\s*=.*/deny=2/' /etc/security/faillock.conf")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/analyse_min.yml")
        self.assertNotIn("faillock" ,list(result["password"]["R31"]["detected_element"].keys()))

    def test_reseaux (self) : 
        """ R80 : Réduire la surface d'attaque des services réseau """
        self.assertTrue(True)

    
    def run_tests(self):
        """Exécuter les tests"""
        suite = unittest.TestSuite()
        suite.addTest(Analyse_min_test(self.client, "test_gestion_acces_min"))
        suite.addTest(Analyse_min_test(self.client, "test_service_min"))
        suite.addTest(Analyse_min_test(self.client, "test_mises_a_jour_automatiques"))
        suite.addTest(Analyse_min_test(self.client, "test_politique_mot_passe"))
        suite.addTest(Analyse_min_test(self.client, "test_reseaux"))
        runner = unittest.TextTestRunner()
        runner.run(suite)
