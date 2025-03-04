import sys
import os
from Config import load_config, ssh_connect
from Tests.Analyse_min_test  import Analyse_min_test
from Tests.Ssh_test import SSH_TEST
from Tests.Test_prompt import CustomTerminal

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
    
    test_ssh = SSH_TEST(client)
    test_analyse_min = Analyse_min_test(client)
    terminal = CustomTerminal()
    terminal.set_ssh_test(test_ssh)
    terminal.set_analyse_min_test(test_analyse_min)



    terminal.run()
    


