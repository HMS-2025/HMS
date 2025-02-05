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
        key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
        client.connect(hostname, port=port, username=username, pkey=key)
        return client
    except Exception as e:
        print(f"Erreur de connexion SSH : {e}")
        return None
