#-------------DÉPENDANCES----------------# 

import paramiko
import yaml
import os

#-------------FONCTIONS OUTILS-----------------# 

# Exécuter la commande données sur le serveur 
def execute_commands(serveur, commands):
    try:
        for command in commands:
            stdin, stdout, stderr = serveur.exec_command(command)
            output = stdout.read().decode()
            print(f"Résultat de `{command}`:\n{output}")
    except Exception as e:
        print(f"Erreur lors de l'exécution des commandes : {e}")


#-------------FONCTIONS PRINCIPALES-----------------# 

def format_ssh_config(config):
    """Formate et affiche la configuration SSH de manière lisible."""
    formatted_config = "\n".join([f"{key}: {value}" for key, value in config.items()])
    print("Configuration SSH du serveur :\n" + formatted_config)
    return formatted_config

def generate_yaml_report(compliance_results, filename, category):
    """Génère un fichier YAML récapitulant les résultats de conformité dans une catégorie donnée, en conservant l'ordre des règles.
       Enregistre le fichier dans le dossier GenerationRapport/RapportAnalyse.
    """
    # Définir le chemin du dossier de sortie
    output_dir = "GenerationRapport/RapportAnalyse"
    
    # S'assurer que le dossier existe
    os.makedirs(output_dir, exist_ok=True)
    
    # Construire le chemin complet du fichier de sortie
    output_path = os.path.join(output_dir, filename)

    # Trier les résultats de conformité par numéro de règle
    sorted_compliance_results = {key: compliance_results[key] for key in sorted(compliance_results.keys(), key=lambda x: int(x[1:]))}
    report_data = {category: sorted_compliance_results}

    # Écriture des résultats dans le fichier YAML
    with open(output_path, "w") as file:
        yaml.safe_dump(report_data, file, default_flow_style=False, sort_keys=False)
    
    print(f"Rapport YAML généré : {output_path}")

def dump_ssh_config(client):
    """Récupère et affiche tout le fichier de configuration SSH du serveur."""
    try:
        stdin, stdout, stderr = client.exec_command("cat /etc/ssh/sshd_config")
        config_data = stdout.read().decode()
        parsed_config = {}
        for line in config_data.split("\n"):
            if line.strip() and not line.strip().startswith("#"):
                key_value = line.split(None, 1)
                if len(key_value) == 2:
                    parsed_config[key_value[0]] = key_value[1]
        format_ssh_config(parsed_config)
        compliance_results = check_compliance(parsed_config)
        generate_yaml_report(compliance_results, "ssh_compliance_report.yaml", "ssh")
        return parsed_config
    except Exception as e:
        print(f"Erreur lors de la récupération de la configuration SSH : {e}")
        return {}

def check_compliance(config):
    """Vérifie la conformité de la configuration SSH selon l'ANSSI et affiche le pourcentage de conformité."""
    anssi_criteria = {
        "R1": ("Protocol", "2"),
        "R2": ("PubkeyAuthentication", "yes"),
        "R3": ("PasswordAuthentication", "no"),
        "R4": ("ChallengeResponseAuthentication", "no"),
        "R5": ("PermitRootLogin", "no"),
        "R6": ("X11Forwarding", "no"),
        "R7": ("AllowTcpForwarding", "no"),
        "R8": ("MaxAuthTries", "2"),
        "R9": ("PermitEmptyPasswords", "no"),
        "R10": ("LoginGraceTime", "30"),
        "R11": ("UsePrivilegeSeparation", "sandbox"),
        "R12": ("AllowUsers", ""),
        "R13": ("AllowGroups", ""),
        "R14": ("Ciphers", "aes256-ctr,aes192-ctr,aes128-ctr"),
        "R15": ("MACs", "hmac-sha2-512,hmac-sha2-256,hmac-sha1"),
        "R16": ("PermitUserEnvironment", "no"),
        "R17": ("AllowAgentForwarding", "no"),
        "R18": ("StrictModes", "yes"),
        "R19": ("HostKey", "/etc/ssh/ssh_host_rsa_key"),
        "R20": ("KexAlgorithms", "diffie-hellman-group-exchange-sha256"),
        "R21": ("AuthorizedKeysFile", ".ssh/authorized_keys"),
        "R22": ("ClientAliveInterval", "300"),
        "R23": ("ClientAliveCountMax", "0"),
        "R24": ("LoginGraceTime", "20"),
        "R25": ("ListenAddress", "192.168.1.1"),
        "R26": ("Port", "22"),
    }
    
    compliance_results = {rule: "false" for rule in sorted(anssi_criteria.keys(), key=lambda x: int(x[1:]))}  # S'assurer que toutes les règles sont présentes et triées
    
    for rule, (key, expected_value) in anssi_criteria.items():
        actual_value = config.get(key, "non défini")
        compliance_results[rule] = "true" if actual_value == expected_value else "false"
    
    compliant_checks = sum(1 for status in compliance_results.values() if status == "true")
    compliance_percentage = (compliant_checks / len(anssi_criteria)) * 100
    
    print("\n--- Évaluation de la conformité SSH ---")
    for rule in sorted(compliance_results.keys(), key=lambda x: int(x[1:])):
        print(f"{rule}: {compliance_results[rule]}")
    
    print(f"\nTaux de conformité : {compliance_percentage:.2f}%")
    return compliance_results

def main():
    """Charge la configuration, l'affiche et exécute les commandes SSH."""
    config = load_config("init.yaml")
    
    if not config:
        print("Configuration invalide.")
        return
    
    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port", 22),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )
    
    if client:
        dump_ssh_config(client)
        client.close()

if __name__ == "__main__":
    main()
