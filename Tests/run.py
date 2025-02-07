import unittest
import os
import yaml
import time
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min

def load_config(path) : 

        # Chargement des secrets
        if not os.path.exists(path):
            raise FileNotFoundError(f"Le fichier de configuration '{path}' est introuvable.")
        
        with open(path, 'r') as config_file:
            return yaml.safe_load(config_file)

class SSH_TEST(unittest.TestCase):
    def __init__(self, client , methodName="runTest"):
        super().__init__(methodName)
        self.client = client

    def test_protocol(self):
        """ ----------- TEST -------------"""
        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Protocol /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


        """ Mettre protocol sur 1 """
        
        stdin, stdout, stderr = self.client.exec_command("echo 'Protocol 1' | sudo tee -a /etc/ssh/sshd_config ")
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        print(result)
        self.assertEqual(result['ssh']['R1'], "false", "Erreur : note")
        
        """ ----------- TEST -------------"""

        """ Clean """
        
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Protocol /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()


        """ Mettre protocol 2 """
        
        stdin, stdout, stderr = self.client.exec_command("echo 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config ; ")
        config_data = stdout.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        """ Test """
        
        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh']['R1'], "true", "Erreur : note")
        
        """ Clean """
        
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^Protocol /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

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
        self.assertEqual(result['ssh_conformite']['R2']['appliquer'], True, "")

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
        
        self.assertEqual(result['ssh_conformite']['R3']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R4']['appliquer'], False, "")

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
        self.assertEqual(result['ssh_conformite']['R5']['appliquer'], False, "")

        """ Clean """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        """ supprimer PermitRootLogin à yes """
        stdin, stdout, stderr = self.client.exec_command("sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config")
        config_data = stdout.read().decode().strip()

        analyse_SSH(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml")
        self.assertEqual(result['ssh_conformite']['R2']['appliquer'], False, "")

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
        self.assertEqual(result['ssh_conformite']['R6']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R7']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R8']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R9']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R10']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R10']['appliquer'], False, "")

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
        self.assertEqual(result['ssh_conformite']['R11']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R12']['appliquer'], False, "")

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
        self.assertEqual(result['ssh_conformite']['R13']['appliquer'], False, "")

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
        
        self.assertEqual(result['ssh_conformite']['R14']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R15']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R16']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R17']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R18']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R19']['appliquer'], True, "")

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
        self.assertEqual(result['ssh_conformite']['R20']['appliquer'], True, "")

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
        suite.addTest(SSH_TEST(self.client, "test_pubkey_authentication"))
        suite.addTest(SSH_TEST(self.client, "test_password_authentication"))
        suite.addTest(SSH_TEST(self.client, "test_challenge_response_authentication"))
        suite.addTest(SSH_TEST(self.client, "test_permit_root_login"))
        suite.addTest(SSH_TEST(self.client, "test_x11_forwarding"))
        suite.addTest(SSH_TEST(self.client, "test_allow_tcp_forwarding"))
        suite.addTest(SSH_TEST(self.client, "test_max_auth_tries"))
        
        
        suite.addTest(SSH_TEST(self.client, "test_no_config_file"))
        suite.addTest(SSH_TEST(self.client, "test_error_config_file"))
        suite.addTest(SSH_TEST(self.client, "test_permit_empty_passwords"))
        suite.addTest(SSH_TEST(self.client, "test_login_grace_time"))
        suite.addTest(SSH_TEST(self.client, "test_use_privilege_separation"))
        suite.addTest(SSH_TEST(self.client, "test_allow_users"))
        suite.addTest(SSH_TEST(self.client, "test_allow_groups"))
        suite.addTest(SSH_TEST(self.client, "test_ciphers"))
        suite.addTest(SSH_TEST(self.client, "test_macs"))
        suite.addTest(SSH_TEST(self.client, "test_permit_user_environment"))
        suite.addTest(SSH_TEST(self.client, "test_allow_agent_forwarding"))
        suite.addTest(SSH_TEST(self.client, "test_strict_modes"))
        suite.addTest(SSH_TEST(self.client, "test_host_key"))
        suite.addTest(SSH_TEST(self.client, "test_kex_algorithms"))
        runner = unittest.TextTestRunner()
        runner.run(suite)

class Analyse_min_test ( unittest.TestCase):
    def __init__(self, client , methodName="runTest"):
        super().__init__(methodName)
        self.client = client

    def test_gestion_acces_min (self) :

        """ ----------- TEST : Détection des utilisateurs inactifs ------------- """

        #Clean avant le test (supprimer d'éventuels utilisateurs de test existants)
        stdin, stdout, stderr=self.client.exec_command("sudo userdel -r test_user1 || true")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo userdel -r test_user2 || true")
        exit_status = stdout.channel.recv_exit_status()


        #Ajouter des utilisateurs inactifs pour le test
        stdin, stdout, stderr=self.client.exec_command("sudo useradd -m -s /bin/bash test_user1")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr=self.client.exec_command("sudo useradd -m -s /bin/bash test_user2")
        exit_status = stdout.channel.recv_exit_status()

        # Vérifier que les utilisateurs inactifs sont bien détectés
        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/gestion_acces_minimal.yml")
        
        self.assertIn("test_user1", result["R30"]["elements_detectes"])
        self.assertIn("test_user2", result["R30"]["elements_detectes"])

        #Désactiver les comptes pour simuler des utilisateurs inactifs
        stdin, stdout, stderr=self.client.exec_command("sudo passwd -l test_user1")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr=self.client.exec_command("sudo passwd -l test_user2")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/gestion_acces_minimal.yml")
        
        self.assertNotIn("test_user1", result["R30"]["elements_detectes"])
        self.assertNotIn("test_user2", result["R30"]["elements_detectes"])

        
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
        result = load_config("GenerationRapport/RapportAnalyse/gestion_acces_minimal.yml")

        #Vérification que le fichier est bien détecté comme non conforme
        self.assertIn("/tmp/test_file_no_owner", result["R53"]["elements_detectes"])
        self.assertEqual(result["R53"]["status"], "Non conforme")

        #Nettoyage après le test
        stdin, stdout, stderr=self.client.exec_command("sudo rm -f /tmp/test_file_no_owner")
        exit_status = stdout.channel.recv_exit_status()


        """ ----------- TEST : Détection des fichiers avec setuid et setgid ------------- """

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

        stdin, stdout, stderr=self.client.exec_command("sudo chmod 755 /tmp/test_suid /tmp/test_sgid")  
        exit_status = stdout.channel.recv_exit_status()

        #Exécution de l'analyse
        analyse_min(self.client)

        #Chargement des résultats
        result = load_config("GenerationRapport/RapportAnalyse/gestion_acces_minimal.yml")

        #Vérification que les fichiers sont bien détectés comme non conformes
        self.assertIn("/tmp/test_suid", result["R56"]["elements_detectes"])
        self.assertIn("/tmp/test_sgid", result["R56"]["elements_detectes"])
        self.assertEqual(result["R56"]["status"], "Non conforme")

        #Nettoyage après le test
        stdin, stdout, stderr=self.client.exec_command("sudo rm -f /tmp/test_suid /tmp/test_sgid")
        exit_status = stdout.channel.recv_exit_status()

    def test_service_min (self) : 
        """ ----------- TEST : Détection des fichiers avec setuid et setgid ------------- """

        # Installation de service interdit 

        stdin, stdout, stderr=self.client.exec_command("sudo apt update ; sudo apt install -y samba nfs-kernel-server")
        exit_status = stdout.channel.recv_exit_status()
        
        
        #Exécution de l'analyse
        analyse_min(self.client)

        #Chargement des résultats
        result = load_config("GenerationRapport/RapportAnalyse/services_minimal.yml")

        #Vérification que les fichiers sont bien détectés comme non conformes
        self.assertIn("samba.service", result["R56"]["services_interdits_detectes"])
        self.assertIn("nfs.service", result["R56"]["services_interdits_detectes"])
        self.assertEqual(result["R56"]["status"], "Non conforme")

        #Nettoyage après le test
        stdin, stdout, stderr=self.client.exec_command("sudo apt remove --purge -y samba nfs-kernel-server")
        exit_status = stdout.channel.recv_exit_status()

    def test_mises_a_jour_automatiques(self):
        """ ----------- TEST : Vérification des mises à jour automatiques ------------- """

        #Nettoyage avant le test (désactiver les mises à jour automatiques)
        stdin, stdout, stderr=self.client.exec_command("unattended-upgrades disable")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/mise_a_jour_minimal.yml")        
        self.assertEqual(result["R61"]["status"], "Non conforme")        
        

        # ------------ Crontab -------------------
        stdin, stdout, stderr = self.client.exec_command('(crontab -l 2>/dev/null; echo "0 3 * * * apt update && apt upgrade -y") | crontab -')        
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/mise_a_jour_minimal.yml")
        self.assertIsNone(result["R61"]["éléments_problématiques"]["Cron Updates"])


        stdin, stdout, stderr = self.client.exec_command("crontab -r")
        exit_status = stdout.channel.recv_exit_status()

        analyse_min(self.client)
        result = load_config("GenerationRapport/RapportAnalyse/mise_a_jour_minimal.yml")
        self.assertIsNone(result["R61"]["éléments_problématiques"]["Cron Updates"])

        
    def run_tests(self):
        """Exécuter les tests"""
        suite = unittest.TestSuite()
        #suite.addTest(Analyse_min_test(self.client, "test_gestion_acces_min"))
        #suite.addTest(Analyse_min_test(self.client, "test_service_min"))
        suite.addTest(Analyse_min_test(self.client, "test_mises_a_jour_automatiques"))
        runner = unittest.TextTestRunner()
        runner.run(suite)    


if __name__=="__main__" : 
    print ( "TEST SSH")


