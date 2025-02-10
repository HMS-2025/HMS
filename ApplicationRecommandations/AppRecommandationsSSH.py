import yaml
import paramiko  # Importation du module paramiko pour SSH

# Mapping des règles ANSSI pour SSH avec leurs commandes associées
rule_commands = {
    "R1": "sudo grep -q '^#\\?Protocol' /etc/ssh/sshd_config && sudo sed -i '/^#\\?Protocol/c\\Protocol 2' /etc/ssh/sshd_config || echo 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R2": "sudo grep -q '^#\\?PubkeyAuthentication' /etc/ssh/sshd_config && sudo sed -i '/^#\\?PubkeyAuthentication/c\\PubkeyAuthentication yes' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R3": "sudo grep -q '^#\\?PasswordAuthentication' /etc/ssh/sshd_config && sudo sed -i '/^#\\?PasswordAuthentication/c\\PasswordAuthentication no' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R4": "sudo grep -q '^#\\?ChallengeResponseAuthentication' /etc/ssh/sshd_config && sudo sed -i '/^#\\?ChallengeResponseAuthentication/c\\ChallengeResponseAuthentication no' /etc/ssh/sshd_config || echo 'ChallengeResponseAuthentication no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R5": "sudo grep -q '^#\\?PermitRootLogin' /etc/ssh/sshd_config && sudo sed -i '/^#\\?PermitRootLogin/c\\PermitRootLogin no' /etc/ssh/sshd_config || echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R6": "sudo grep -q '^#\\?X11Forwarding' /etc/ssh/sshd_config && sudo sed -i '/^#\\?X11Forwarding/c\\X11Forwarding no' /etc/ssh/sshd_config || echo 'X11Forwarding no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R7": "sudo grep -q '^#\\?AllowTcpForwarding' /etc/ssh/sshd_config && sudo sed -i '/^#\\?AllowTcpForwarding/c\\AllowTcpForwarding no' /etc/ssh/sshd_config || echo 'AllowTcpForwarding no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R8": "sudo grep -q '^#\\?MaxAuthTries' /etc/ssh/sshd_config && sudo sed -i '/^#\\?MaxAuthTries/c\\MaxAuthTries 2' /etc/ssh/sshd_config || echo 'MaxAuthTries 2' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R9": "sudo grep -q '^#\\?PermitEmptyPasswords' /etc/ssh/sshd_config && sudo sed -i '/^#\\?PermitEmptyPasswords/c\\PermitEmptyPasswords no' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R10": "sudo grep -q '^#\\?LoginGraceTime' /etc/ssh/sshd_config && sudo sed -i '/^#\\?LoginGraceTime/c\\LoginGraceTime 30' /etc/ssh/sshd_config || echo 'LoginGraceTime 30' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R11": "sudo grep -q '^#\\?UsePrivilegeSeparation' /etc/ssh/sshd_config && sudo sed -i '/^#\\?UsePrivilegeSeparation/c\\UsePrivilegeSeparation sandbox' /etc/ssh/sshd_config || echo 'UsePrivilegeSeparation sandbox' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R12": "sudo grep -q '^#\\?AllowUsers' /etc/ssh/sshd_config && sudo sed -i '/^#\\?AllowUsers/c\\AllowUsers' /etc/ssh/sshd_config || echo 'AllowUsers' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R13": "sudo grep -q '^#\\?AllowGroups' /etc/ssh/sshd_config && sudo sed -i '/^#\\?AllowGroups/c\\AllowGroups' /etc/ssh/sshd_config || echo 'AllowGroups' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R14": "sudo grep -q '^#\\?Ciphers' /etc/ssh/sshd_config && sudo sed -i '/^#\\?Ciphers/c\\Ciphers aes256-ctr,aes192-ctr,aes128-ctr' /etc/ssh/sshd_config || echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R15": "sudo grep -q '^#\\?MACs' /etc/ssh/sshd_config && sudo sed -i '/^#\\?MACs/c\\MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1' /etc/ssh/sshd_config || echo 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R16": "sudo grep -q '^#\\?PermitUserEnvironment' /etc/ssh/sshd_config && sudo sed -i '/^#\\?PermitUserEnvironment/c\\PermitUserEnvironment no' /etc/ssh/sshd_config || echo 'PermitUserEnvironment no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R17": "sudo grep -q '^#\\?AllowAgentForwarding' /etc/ssh/sshd_config && sudo sed -i '/^#\\?AllowAgentForwarding/c\\AllowAgentForwarding no' /etc/ssh/sshd_config || echo 'AllowAgentForwarding no' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R18": "sudo grep -q '^#\\?StrictModes' /etc/ssh/sshd_config && sudo sed -i '/^#\\?StrictModes/c\\StrictModes yes' /etc/ssh/sshd_config || echo 'StrictModes yes' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R19": "sudo grep -q '^#\\?HostKey' /etc/ssh/sshd_config && sudo sed -i '/^#\\?HostKey/c\\HostKey /etc/ssh/ssh_host_rsa_key' /etc/ssh/sshd_config || echo 'HostKey /etc/ssh/ssh_host_rsa_key' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R20": "sudo grep -q '^#\\?KexAlgorithms' /etc/ssh/sshd_config && sudo sed -i '/^#\\?KexAlgorithms/c\\KexAlgorithms diffie-hellman-group-exchange-sha256' /etc/ssh/sshd_config || echo 'KexAlgorithms diffie-hellman-group-exchange-sha256' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R21": "sudo grep -q '^#\\?AuthorizedKeysFile' /etc/ssh/sshd_config && sudo sed -i '/^#\\?AuthorizedKeysFile/c\\AuthorizedKeysFile .ssh/authorized_keys' /etc/ssh/sshd_config || echo 'AuthorizedKeysFile .ssh/authorized_keys' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R22": "sudo grep -q '^#\\?ClientAliveInterval' /etc/ssh/sshd_config && sudo sed -i '/^#\\?ClientAliveInterval/c\\ClientAliveInterval 300' /etc/ssh/sshd_config || echo 'ClientAliveInterval 300' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R23": "sudo grep -q '^#\\?ClientAliveCountMax' /etc/ssh/sshd_config && sudo sed -i '/^#\\?ClientAliveCountMax/c\\ClientAliveCountMax 0' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 0' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R24": "sudo grep -q '^#\\?LoginGraceTime' /etc/ssh/sshd_config && sudo sed -i '/^#\\?LoginGraceTime/c\\LoginGraceTime 20' /etc/ssh/sshd_config || echo 'LoginGraceTime 20' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R25": "sudo grep -q '^#\\?ListenAddress' /etc/ssh/sshd_config && sudo sed -i '/^#\\?ListenAddress/c\\ListenAddress 192.168.1.1' /etc/ssh/sshd_config || echo 'ListenAddress 192.168.1.1' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "R26": "sudo grep -q '^#\\?Port' /etc/ssh/sshd_config && sudo sed -i '/^#\\?Port/c\\Port 22' /etc/ssh/sshd_config || echo 'Port 22' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart ssh"
}

def load_yaml(yaml_file):
    """Charger le fichier YAML"""
    with open(yaml_file, 'r') as file:
        return yaml.safe_load(file)

def save_yaml(yaml_file, config):
    """Sauvegarder la configuration dans le fichier YAML"""
    with open(yaml_file, 'w') as file:
        yaml.safe_dump(config, file, default_flow_style=False)

def apply_command(command, client):
    """Appliquer la commande via le client SSH et retourner True si elle réussit"""
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        if error:
            print(f"Erreur: {error}")
            return False
        print(f"Sortie: {output}")
        return True
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande: {e}")
        return False

def apply_selected_recommendationsSSH(yaml_file, client):
    """Appliquer les recommandations sélectionnées et mettre à jour le fichier YAML"""
    # Charger la configuration YAML
    config = load_yaml(yaml_file)

    for rule, details in config.items():
        # Vérifier si la règle a une clé 'appliquer' et est définie sur False
        if isinstance(details, dict) and not details.get("appliquer", False):
            # Si 'appliquer' est False et que la règle existe dans rule_commands
            if rule in rule_commands:
                command = rule_commands[rule]
                success = apply_command(command, client)

                # Décommenter et mettre à jour la clé 'appliquer' avec True
                details["appliquer"] = True
                details["status"] = "Conforme" if success else "Non conforme"
                
    # Sauvegarder les modifications dans le fichier YAML
    save_yaml(yaml_file, config)

# Appliquer les recommandations
# apply_selected_recommendationsSSH('file.yaml', client)
