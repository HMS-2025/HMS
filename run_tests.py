import sys
import os
from Config import load_config, ssh_connect
from Tests.Analyse_min_test  import Analyse_min_test
from Tests.Ssh_test import SSH_TEST

if __name__ == "__main__":
    #main()
    print("\n--- Début de l'application des recommandations générales ---\n")

    # Charger la configuration SSH
    config = load_config("ssh.yaml")
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
    
    
    Tests = Analyse_min_test(client)
    Tests.run_tests()

    


