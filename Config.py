#-------------DÉPENDANCES----------------# 

import paramiko
import yaml
import os 

#-------------FONCTIONS OUTILS-----------------# 

# Importer la config depuis le yaml 
def load_config(yaml_file):
    try:
        with open(yaml_file, "r") as file:
            config = yaml.safe_load(file)
        return config.get("ssh", {})
    except Exception as e:
        print(f"Erreur lors du chargement du fichier YAML : {e}")
        return {}

# Se connecter au SSH
def ssh_connect(hostname, port, username, key_path, passphrase=None):
    if not key_path or not os.path.isfile(key_path):
        print(f"Erreur : Clé SSH introuvable au chemin spécifié : {key_path}")
        exit(1)
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key = None
        key_classes = [paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key]
        
        for key_class in key_classes:
            try:
                key = key_class.from_private_key_file(key_path, password=passphrase)
                break 
            except paramiko.ssh_exception.SSHException:
                continue  
        
        if key is None:
            raise ValueError("Format de clé SSH non pris en charge ou fichier invalide")
        
        key_size = key.get_bits()
        print(f"Taille de la clé SSH utilisée : {key_size} bits")
        
        # Vérifier si la taille de la clé respecte les standards minimaux
        if isinstance(key, paramiko.RSAKey) and key_size < 2048:
            print("Avertissement : La clé RSA utilisée est inférieure à 2048 bits, ce qui est considéré comme non sécurisé.")
        elif isinstance(key, paramiko.ECDSAKey) and key_size < 256:
            print("Avertissement : La clé ECDSA utilisée est inférieure à 256 bits, ce qui est considéré comme non sécurisé.")
        elif isinstance(key, paramiko.DSSKey) and key_size < 1024:
            print("Avertissement : La clé DSS utilisée est inférieure à 1024 bits, ce qui est considéré comme non sécurisé.")
        
        client.connect(hostname, port=port, username=username, pkey=key)
        return client
    except Exception as e:
        print(f"Erreur de connexion SSH : {e}")
        return None
