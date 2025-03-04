import unittest
import os
import yaml
import time
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendationsSSH
def load_config(path) : 

        # Chargement des secrets
        if not os.path.exists(path):
            raise FileNotFoundError(f"Le fichier de configuration '{path}' est introuvable.")
        
        with open(path, 'r') as config_file:
            return yaml.safe_load(config_file)

class Application_ssh_test (unittest.TestCase):
    def __init__(self, client , methodName="runTest"):
        super().__init__(methodName)
        self.client = client
    def test_pubkey_authentication(self):

        """ ----------- test_application R2: PubkeyAuthentication -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PubkeyAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()
        
        """ Mettre PubkeyAuthentication à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'PubkeyAuthentication no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        print(result)
        self.assertEqual(result['ssh_conformite']['R2']['apply'], True, "")
        
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PubkeyAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()


    def test_password_authentication(self):

        """ ----------- TEST R3: PasswordAuthentication -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre PasswordAuthentication à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'PasswordAuthentication yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R3']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_challenge_response_authentication(self):
        """ ----------- TEST R4: ChallengeResponseAuthentication -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^ChallengeResponseAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre ChallengeResponseAuthentication à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'ChallengeResponseAuthentication yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 
        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R4']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^ChallengeResponseAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_permit_root_login(self):
        """ ----------- TEST R5: PermitRootLogin -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre PermitRootLogin à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'PermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R5']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        """ supprimer PermitRootLogin"""
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        #Lancer l'application pour corriger ( ajout automatique de l'option )

        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R2']['apply'], True, "")


    def test_x11_forwarding(self):
        """ ----------- TEST R6: X11Forwarding -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^X11Forwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()
        
        """ mettre l'option en commentaire """
        stdin, stdout, stderr = self.client.exec_command("echo '#X11Forwarding no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R6']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^#X11Forwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_allow_tcp_forwarding(self):
        """ ----------- TEST R7: AllowTcpForwarding -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowTcpForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre AllowTcpForwarding à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowTcpForwarding yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R7']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowTcpForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()


    def test_max_auth_tries(self):
        """ ----------- TEST R8: MaxAuthTries -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre MaxAuthTries à 10 pour creer une erreur """
        stdin, stdout, stderr = self.client.exec_command("echo 'MaxAuthTries 10' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R8']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_permit_empty_passwords(self):
        """ ----------- TEST R9: PermitEmptyPasswords -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitEmptyPasswords /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre PermitEmptyPasswords à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'PermitEmptyPasswords yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R9']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitEmptyPasswords /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_login_grace_time(self):
        """ ----------- TEST R10: LoginGraceTime -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre l'option en commentaire LoginGraceTime valeur par default 2min"""
        stdin, stdout, stderr = self.client.exec_command("echo '#LoginGraceTime 30' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R10']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        """ Mettre LoginGraceTime à 60 """
        stdin, stdout, stderr = self.client.exec_command("echo 'LoginGraceTime 60' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 


        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R10']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()



    def test_use_privilege_separation(self):
        """ ----------- TEST R11: UsePrivilegeSeparation -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^UsePrivilegeSeparation /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre UsePrivilegeSeparation en commentaire """
        stdin, stdout, stderr = self.client.exec_command("#echo 'UsePrivilegeSeparation sandbox' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R11']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^UsePrivilegeSeparation /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_allow_users(self):
        """ ----------- TEST R12: AllowUsers -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowUsers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre AllowUsers vide """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowUsers ' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R12']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowUsers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


    def test_allow_groups(self):
        """ ----------- TEST R13: AllowGroups -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowGroups /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre AllowGroups vide """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowGroups ' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R13']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowGroups /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


    def test_ciphers(self):
        """ ----------- TEST R14: Ciphers -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Ciphers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre ajouter aes128-cbc """
        stdin, stdout, stderr = self.client.exec_command("echo 'Ciphers aes256-ctr,aes192-ctr,aes128-cbc' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        
        self.assertEqual(result['ssh_conformite']['R14']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Ciphers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_macs(self):
        """----------- TEST R15: MACs -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MACs /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre MACs à hmac-sha2-512,hmac-sha2-256,hmac-sha1 """
        stdin, stdout, stderr = self.client.exec_command("echo 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R15']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MACs /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_permit_user_environment(self):
        """ ----------- TEST R16: PermitUserEnvironment -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitUserEnvironment /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre PermitUserEnvironment à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'PermitUserEnvironment yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 


        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R16']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitUserEnvironment /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_allow_agent_forwarding(self):
        """ ----------- TEST R17: AllowAgentForwarding -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowAgentForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre AllowAgentForwarding à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowAgentForwarding yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 


        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R17']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowAgentForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_strict_modes(self):
        """ ----------- TEST R18: StrictModes -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^StrictModes /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre StrictModes à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'StrictModes no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        #Lancer l'application pour corriger 

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R18']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^StrictModes /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_no_config_file(self):
        """Test si le fichier de configuration SSH est absent"""
        self.skipTest("Test ignoré")

    def test_error_config_file(self):
        """ Test d'une mauvaise configuration SSH """
        self.skipTest("Test ignoré")

    def run_tests (self):
        """Exécuter les tests"""

        suite = unittest.TestSuite()

        suite.addTest(Application_ssh(self.client, "test_pubkey_authentication"))
        suite.addTest(Application_ssh(self.client, "test_password_authentication"))
        suite.addTest(Application_ssh(self.client, "test_challenge_response_authentication"))
        suite.addTest(Application_ssh(self.client, "test_permit_root_login"))
        suite.addTest(Application_ssh(self.client, "test_x11_forwarding"))
        suite.addTest(Application_ssh(self.client, "test_allow_tcp_forwarding"))
        suite.addTest(Application_ssh(self.client, "test_max_auth_tries"))

        suite.addTest(Application_ssh(self.client, "test_no_config_file"))
        suite.addTest(Application_ssh(self.client, "test_error_config_file"))
        suite.addTest(Application_ssh(self.client, "test_permit_empty_passwords"))
        suite.addTest(Application_ssh(self.client, "test_login_grace_time"))
        suite.addTest(Application_ssh(self.client, "test_use_privilege_separation"))
        suite.addTest(Application_ssh(self.client, "test_allow_users"))
        suite.addTest(Application_ssh(self.client, "test_allow_groups"))
        suite.addTest(Application_ssh(self.client, "test_ciphers"))

        suite.addTest(Application_ssh(self.client, "test_macs"))
        suite.addTest(Application_ssh(self.client, "test_permit_user_environment"))
        suite.addTest(Application_ssh(self.client, "test_allow_agent_forwarding"))
        suite.addTest(Application_ssh(self.client, "test_strict_modes"))
        suite.addTest(Application_ssh(self.client, "test_host_key"))
        suite.addTest(Application_ssh(self.client, "test_kex_algorithms"))

        runner = unittest.TextTestRunner()
        runner.run(suite)

class Analyse_ssh_test(unittest.TestCase):
    def __init__(self, client , methodName="runTest"):
        super().__init__(methodName)
        self.client = client


    def test_pubkey_authentication(self):

        """ ----------- TEST R2: PubkeyAuthentication -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PubkeyAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre PubkeyAuthentication à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'PubkeyAuthentication yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()


        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        print(result)
        self.assertEqual(result['ssh_conformite']['R2']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PubkeyAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()


    def test_password_authentication(self):

        """ ----------- TEST R3: PasswordAuthentication -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


        """ Mettre PasswordAuthentication à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()
        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        
        self.assertEqual(result['ssh_conformite']['R3']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_challenge_response_authentication(self):
        """ ----------- TEST R4: ChallengeResponseAuthentication -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^ChallengeResponseAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre ChallengeResponseAuthentication à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'ChallengeResponseAuthentication yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()
        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R4']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^ChallengeResponseAuthentication /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_permit_root_login(self):
        """ ----------- TEST R5: PermitRootLogin -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre PermitRootLogin à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'PermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()
        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R5']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        """ supprimer PermitRootLogin à yes """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R2']['apply'], False, "")

    def test_x11_forwarding(self):
        """ ----------- TEST R6: X11Forwarding -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^X11Forwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()
        
        """ Mettre X11Forwarding à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'X11Forwarding no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()
        
        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R6']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^X11Forwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_allow_tcp_forwarding(self):
        """ ----------- TEST R7: AllowTcpForwarding -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowTcpForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre AllowTcpForwarding à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowTcpForwarding no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R7']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowTcpForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    # Continue for the remaining rules R8 to R26

    def test_max_auth_tries(self):
        """ ----------- TEST R8: MaxAuthTries -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre MaxAuthTries à 2 """
        stdin, stdout, stderr = self.client.exec_command("echo 'MaxAuthTries 2' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R8']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_permit_empty_passwords(self):
        """ ----------- TEST R9: PermitEmptyPasswords -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitEmptyPasswords /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre PermitEmptyPasswords à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R9']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitEmptyPasswords /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_login_grace_time(self):
        """ ----------- TEST R10: LoginGraceTime -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre LoginGraceTime à 30 """
        stdin, stdout, stderr = self.client.exec_command("echo 'LoginGraceTime 30' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R10']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre LoginGraceTime à 30 """
        stdin, stdout, stderr = self.client.exec_command("echo 'LoginGraceTime 60' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R10']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^LoginGraceTime /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()



    def test_use_privilege_separation(self):
        """ ----------- TEST R11: UsePrivilegeSeparation -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^UsePrivilegeSeparation /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre UsePrivilegeSeparation à sandbox """
        stdin, stdout, stderr = self.client.exec_command("echo 'UsePrivilegeSeparation sandbox' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R11']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^UsePrivilegeSeparation /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_allow_users(self):
        """ ----------- TEST R12: AllowUsers -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowUsers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre AllowUsers vide """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowUsers ' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R12']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowUsers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


    def test_allow_groups(self):
        """ ----------- TEST R13: AllowGroups -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowGroups /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre AllowGroups vide """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowGroups ' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        
        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R13']['apply'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowGroups /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


    def test_ciphers(self):
        """ ----------- TEST R14: Ciphers -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Ciphers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        
        """ Mettre Ciphers à aes256-ctr,aes192-ctr,aes128-ctr """
        stdin, stdout, stderr = self.client.exec_command("echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        
        self.assertEqual(result['ssh_conformite']['R14']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Ciphers /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_macs(self):
        """ ----------- TEST R15: MACs -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MACs /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre MACs à hmac-sha2-512,hmac-sha2-256,hmac-sha1 """
        stdin, stdout, stderr = self.client.exec_command("echo 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R15']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^MACs /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_permit_user_environment(self):
        """ ----------- TEST R16: PermitUserEnvironment -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitUserEnvironment /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre PermitUserEnvironment à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'PermitUserEnvironment no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R16']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitUserEnvironment /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_allow_agent_forwarding(self):
        """ ----------- TEST R17: AllowAgentForwarding -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowAgentForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre AllowAgentForwarding à no """
        stdin, stdout, stderr = self.client.exec_command("echo 'AllowAgentForwarding no' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R17']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^AllowAgentForwarding /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_strict_modes(self):
        """ ----------- TEST R18: StrictModes -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^StrictModes /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre StrictModes à yes """
        stdin, stdout, stderr = self.client.exec_command("echo 'StrictModes yes' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R18']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^StrictModes /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_host_key(self):
        """ ----------- TEST R19: HostKey -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^HostKey /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre HostKey à /etc/ssh/ssh_host_rsa_key """
        stdin, stdout, stderr = self.client.exec_command("echo 'HostKey /etc/ssh/ssh_host_rsa_key' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R19']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^HostKey /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_kex_algorithms(self):
        """ ----------- TEST R20: KexAlgorithms -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^KexAlgorithms /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Mettre KexAlgorithms à diffie-hellman-group-exchange-sha256 """
        stdin, stdout, stderr = self.client.exec_command("echo 'KexAlgorithms diffie-hellman-group-exchange-sha256' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R20']['apply'], True, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^KexAlgorithms /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

    def test_no_config_file(self):
        """Test si le fichier de configuration SSH est absent"""
        self.skipTest("Test ignoré")

    def test_error_config_file(self):
        """Test d'une mauvaise configuration SSH"""
        self.skipTest("Test ignoré")

    def run_tests(self):
        """Exécuter les tests"""
        suite = unittest.TestSuite()
        suite.addTest(Analyse_ssh_test(self.client, "test_pubkey_authentication"))
        suite.addTest(Analyse_ssh_test(self.client, "test_password_authentication"))
        suite.addTest(Analyse_ssh_test(self.client, "test_challenge_response_authentication"))
        suite.addTest(Analyse_ssh_test(self.client, "test_permit_root_login"))
        suite.addTest(Analyse_ssh_test(self.client, "test_x11_forwarding"))
        suite.addTest(Analyse_ssh_test(self.client, "test_allow_tcp_forwarding"))
        suite.addTest(Analyse_ssh_test(self.client, "test_max_auth_tries"))
        
        
        suite.addTest(Analyse_ssh_test(self.client, "test_no_config_file"))
        suite.addTest(Analyse_ssh_test(self.client, "test_error_config_file"))
        suite.addTest(Analyse_ssh_test(self.client, "test_permit_empty_passwords"))
        suite.addTest(Analyse_ssh_test(self.client, "test_login_grace_time"))
        suite.addTest(Analyse_ssh_test(self.client, "test_use_privilege_separation"))
        suite.addTest(Analyse_ssh_test(self.client, "test_allow_users"))
        suite.addTest(Analyse_ssh_test(self.client, "test_allow_groups"))
        suite.addTest(Analyse_ssh_test(self.client, "test_ciphers"))
        suite.addTest(Analyse_ssh_test(self.client, "test_macs"))
        suite.addTest(Analyse_ssh_test(self.client, "test_permit_user_environment"))
        suite.addTest(Analyse_ssh_test(self.client, "test_allow_agent_forwarding"))
        suite.addTest(Analyse_ssh_test(self.client, "test_strict_modes"))
        suite.addTest(Analyse_ssh_test(self.client, "test_host_key"))
        suite.addTest(Analyse_ssh_test(self.client, "test_kex_algorithms"))
        runner = unittest.TextTestRunner()
        runner.run(suite)
