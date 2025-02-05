import yaml
import subprocess

# Mapping des règles ANSSI pour SSH avec leurs commandes associées
rule_commands = {
    "R1": "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R2": "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R3": "echo 'AllowUsers user1 user2' >> /etc/ssh/sshd_config && systemctl restart sshd",
    "R4": "sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R5": "echo 'AllowGroups sshusers' >> /etc/ssh/sshd_config && systemctl restart sshd",
    "R6": "sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R7": "sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R8": "sed -i 's/^UseDNS.*/UseDNS no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R9": "sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R10": "sed -i 's/^ListenAddress.*/ListenAddress 192.168.1.1/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R11": "sed -i 's/^AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R12": "sed -i 's/^KexAlgorithms.*/KexAlgorithms curve25519-sha256/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R13": "sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config && sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R14": "sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R15": "chmod 600 ~/.ssh/authorized_keys",
    "R16": "sed -i 's|^Banner.*|Banner /etc/issue.net|' /etc/ssh/sshd_config && systemctl restart sshd",
    "R17": "sed -i 's/^Compression.*/Compression no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R18": "sed -i 's/^MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R19": "sed -i 's/^AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R20": "sed -i 's/^Port.*/Port 22/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R21": "sed -i 's/^GSSAPIAuthentication.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R22": "sed -i 's/^AuthenticationMethods.*/AuthenticationMethods publickey/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R23": "sed -i 's/^LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R24": "echo 'sshd: 192.168.1.0/24' >> /etc/hosts.allow",
    "R25": "sed -i 's/^KerberosAuthentication.*/KerberosAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd",
    "R26": "echo 'ProxyJump bastion_host' >> ~/.ssh/config"
}

def load_yaml(yaml_file):
    """Charger le fichier YAML"""
    with open(yaml_file, 'r') as file:
        return yaml.safe_load(file)

def save_yaml(yaml_file, config):
    """Sauvegarder la configuration dans le fichier YAML"""
    with open(yaml_file, 'w') as file:
        yaml.safe_dump(config, file, default_flow_style=False)

def apply_command(command):
    """Appliquer la commande et retourner True si elle réussit"""
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def apply_selected_recommendations(yaml_file):
    """Appliquer les recommandations sélectionnées et mettre à jour le fichier YAML"""
    # Charger la configuration YAML
    config = load_yaml(yaml_file)

    for rule, details in config.items():
        # Vérifier si la règle a une clé 'appliquer' et est définie sur False
        if isinstance(details, dict) and not details.get("appliquer", False):
            # Si 'appliquer' est False et que la règle existe dans rule_commands
            if rule in rule_commands:
                command = rule_commands[rule]
                success = apply_command(command)
                
                # Mettre à jour la clé 'appliquer' avec True ou False
                config[rule]["appliquer"] = success
                config[rule]["status"] = "Conforme" if success else "Non conforme"
                
    # Sauvegarder les modifications dans le fichier YAML
    save_yaml(yaml_file, config)

# Exemple d'utilisation
# apply_selected_recommendations('file.yaml')