from Config import load_config, ssh_connect
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendations
from ApplicationRecommandations.AppRecommandationsMin import  apply_recommendations

# Fonction principale du script
# Charge la configuration SSH, établit la connexion et lance les analyses

def main():
    # Charger la configuration depuis le fichier YAML
    config = load_config("ssh.yaml")
    if not config:
        print("Configuration invalide")
        return

    # Établir la connexion SSH avec les paramètres de configuration
    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )

    # Vérifier si la connexion SSH est établie
    if not client:
        print("Échec de la connexion SSH")
        return
    
    print("Lors de l'exécution de ce script, la commande sudo sera exécutée.")
    print("Veuillez donc vérifier que vous avez les droits nécessaires sur le système. (sudo | root)")
    
    # Exécuter l'analyse de la configuration SSH
    print("\n--- Début de l'analyse SSH ---\n")
    analyse_SSH(client)
    
    # Exécuter l'analyse du niveau minimal
    analyse_min(client)

    # Fermer la connexion SSH après l'analyse
    client.close()

# Point d'entrée du script
if __name__ == "__main__":
    main()
