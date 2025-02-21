import sys
from Config import load_config, ssh_connect
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min, analyse_moyen
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendationsSSH
from ApplicationRecommandations.AppRecommandationsMin import application_recommandations_min
from John import install_john, use_john, retrieve_hash_files  # Import John The Ripper functions

# Function to display the main menu
def display_main_menu():
    print("\n===== Main Menu =====")
    print("1 - Run an analysis")
    print("2 - Apply recommendations")
    print("3 - Apply SSH recommendations")
    print("4 - Retrieve hash files from server")  # Needs SSH connection
    print("5 - Use John The Ripper")  # Runs John locally
    print("6 - Exit")
    return input("Select an option (1-6): ")

# Function to display the analysis levels
def select_analysis_level():
    print("\n===== Select Analysis Level =====")
    print("1 - Global analysis")
    print("2 - Minimal analysis")
    print("3 - Intermediate analysis")
    print("4 - Advanced analysis")
    print("5 - SSH configuration analysis only")
    print("6 - Return to the main menu")
    return input("Select an option (1-6): ")

# Main script function
def main():
    while True:
        menu_choice = display_main_menu()

        if menu_choice == "1":  # Run an analysis
            analysis_choice = select_analysis_level()

            if analysis_choice in ["1", "2", "3", "4", "5"]:
                # Load SSH configuration
                config = load_config("ssh.yaml")
                if not config:
                    print("Invalid configuration")
                    continue

                # Establish SSH connection
                client = ssh_connect(
                    hostname=config.get("hostname"),
                    port=config.get("port"),
                    username=config.get("username"),
                    key_path=config.get("key_path"),
                    passphrase=config.get("passphrase")
                )

                if not client:
                    print("SSH connection failed")
                    continue
                
                print("\n--- Starting analysis ---\n")

                # Run the analysis based on user selection
                if analysis_choice == "1":
                    print("\n[Analysis] Running global analysis...")
                    analyse_min(client)  # Future analyses can be added here

                elif analysis_choice == "2":
                    print("\n[Analysis] Running minimal analysis...")
                    analyse_min(client)

                elif analysis_choice == "3":
                    print("\n[Analysis] Running intermediate analysis...")
                    analyse_moyen(client)  # Intermediate analysis

                elif analysis_choice == "4":
                    print("\n[Analysis] Running advanced analysis...")
                    # Add the function analyse_renforcee(client) here

                elif analysis_choice == "5":
                    print("\n[Analysis] Running SSH configuration analysis only...")
                    analyse_SSH(client)

                # Close the connection after analysis
                client.close()
                print("\n--- Analysis complete ---\n")

            elif analysis_choice == "6":
                continue

        elif menu_choice == "2":  # Apply general recommendations
            print("\n--- Starting general recommendations application ---\n")

            # Load SSH configuration
            config = load_config("ssh.yaml")
            if not config:
                print("Invalid configuration")
                continue

            # Establish SSH connection
            client = ssh_connect(
                hostname=config.get("hostname"),
                port=config.get("port"),
                username=config.get("username"),
                key_path=config.get("key_path"),
                passphrase=config.get("passphrase")
            )

            if not client:
                print("SSH connection failed")
                continue

            # Apply general recommendations (minimal level)
            path_report = "./GenerationRapport/RapportAnalyse/"  # Folder containing reports
            application_recommandations_min(path_report, client)

            # Close the connection after application
            client.close()
            print("\n--- General recommendations application complete ---\n")

        elif menu_choice == "3":  # Apply specific SSH recommendations
            print("\n--- Starting SSH recommendations application ---\n")

            # Load SSH configuration
            config = load_config("ssh.yaml")
            if not config:
                print("Invalid configuration")
                continue

            # Establish SSH connection
            client = ssh_connect(
                hostname=config.get("hostname"),
                port=config.get("port"),
                username=config.get("username"),
                key_path=config.get("key_path"),
                passphrase=config.get("passphrase")
            )

            if not client:
                print("SSH connection failed")
                continue

            # Apply only SSH recommendations
            apply_selected_recommendationsSSH("testRecommandationSSH.yaml", client)

            # Close the connection after application
            client.close()
            print("\n--- SSH recommendations application complete ---\n")

        elif menu_choice == "4":  # Retrieve hash files from server
            print("\n--- Retrieving hash files from server ---\n")

            # Load SSH configuration
            config = load_config("ssh.yaml")
            if not config:
                print("Invalid configuration")
                continue

            # Establish SSH connection
            client = ssh_connect(
                hostname=config.get("hostname"),
                port=config.get("port"),
                username=config.get("username"),
                key_path=config.get("key_path"),
                passphrase=config.get("passphrase")
            )

            if not client:
                print("SSH connection failed")
                continue

            # Retrieve the hash files
            retrieve_hash_files(client)

            # Close SSH connection
            client.close()
            print("\n--- Hash files retrieval complete ---\n")

        elif menu_choice == "5":  # Use John The Ripper locally
            print("\n--- Running John The Ripper ---\n")
            use_john()  # Call the John The Ripper module

        elif menu_choice == "6":  # Exit
            print("Exiting program...")
            sys.exit()

        else:
            print("Invalid option, please select a valid choice.")

# Script entry point
if __name__ == "__main__":
    main()
