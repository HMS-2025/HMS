import sys
from Config import load_config, ssh_connect
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendationsSSH
from ApplicationRecommandations.AppRecommandationsMin import apply_recommendationsMin
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min, analyse_moyen
from Tests.run import Analyse_min_test , SSH_TEST
# Fonction pour afficher le menu principal
def afficher_menu():
    print("\n===== Menu Principal =====")
    print("1 - Exécuter une analyse")
    print("2 - Appliquer les recommandations")
    print("3 - Appliquer les recommandations SSH")
    print("4 - Quitter")
    return input("Sélectionnez une option (1-4) : ")

# Fonction pour afficher les niveaux d'analyse
def selectionner_niveau_analyse():
    print("\n===== Sélection du niveau d'analyse =====")
    print("1 - Analyse globale")
    print("2 - Analyse minimale")
    print("3 - Analyse intermédiaire")
    print("4 - Analyse renforcée")
    print("5 - Analyse de la configuration SSH uniquement")
    print("6 - Retour au menu principal")
    return input("Sélectionnez une option (1-6) : ")

# Fonction principale du script
def main():
    while True:
        choix_menu = afficher_menu()

        if choix_menu == "1":  # Exécuter une analyse
            choix_analyse = selectionner_niveau_analyse()

            if choix_analyse in ["1", "2", "3", "4", "5"]:
                # Charger la configuration SSH
                config = load_config("ssh.yaml")
                if not config:
                    print("Configuration invalide")
                    continue

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
                    continue
                
                print("\n--- Début de l'analyse ---\n")

                # Lancer l'analyse en fonction du choix de l'utilisateur
                if choix_analyse == "1":
                    print("\n[Analyse] Exécution de l'analyse globale...")
                    analyse_min(client)  # Ajout des analyses futures ici

                elif choix_analyse == "2":
                    print("\n[Analyse] Exécution de l'analyse minimale...")
                    analyse_min(client)

                elif choix_analyse == "3":
                    print("\n[Analyse] Exécution de l'analyse intermédiaire...")
                    analyse_moyen(client)  # Ajout de l'analyse intermédiaire

                elif choix_analyse == "4":
                    print("\n[Analyse] Exécution de l'analyse renforcée...")
                    # Ajouter ici la fonction analyse_renforcee(client)

                elif choix_analyse == "5":
                    print("\n[Analyse] Exécution de l'analyse SSH uniquement...")
                    analyse_SSH(client)

                # Fermer la connexion après l'analyse
                client.close()
                print("\n--- Fin de l'analyse ---\n")

            elif choix_analyse == "6":
                continue

        elif choix_menu == "2":  # Appliquer les recommandations générales
            print("\n--- Début de l'application des recommandations générales ---\n")

            # Charger la configuration SSH
            config = load_config("ssh.yaml")
            if not config:
                print("Configuration invalide")
                continue

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
                continue

            # Appliquer les recommandations générales (niveau minimal)
            #verification d'existance des rapports yaml de chaque thematiques
            path_report = "./GenerationRapport/RapportAnalyse/"  # Dossier contenant les rapports

            apply_recommendationsMin(path_report, client)

            # Fermer la connexion après application
            client.close()
            print("\n--- Fin de l'application des recommandations générales ---\n")

        elif choix_menu == "3":  # Appliquer les recommandations spécifiques SSH
            print("\n--- Début de l'application des recommandations SSH ---\n")

            # Charger la configuration SSH
            config = load_config("ssh.yaml")
            if not config:
                print("Configuration invalide")
                continue

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
                continue

            # Appliquer uniquement les recommandations SSH
            apply_selected_recommendationsSSH("testRecommandationSSH.yaml", client)

            # Fermer la connexion après application
            client.close()
            print("\n--- Fin de l'application des recommandations SSH ---\n")

        elif choix_menu == "4":  # Quitter
            print("Fermeture du programme...")
            sys.exit()

        else:
            print("Option invalide, veuillez choisir une option correcte.")

# Point d'entrée du script
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
    
    Tests = SSH_TEST(client)
    Tests.run_tests()