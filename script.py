import sys
from Config import load_config, ssh_connect
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min, analyse_moyen
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendationsSSH
from ApplicationRecommandations.AppRecommandationsMin import application_recommandations_min
from gui import Gui
import john  # Import the module containing all John The Ripper functions

# Function to display the main menu
def display_main_menu():
    print("\n===== Main Menu =====")
    print("1 - Run analysis")
    print("2 - Apply recommendations")
    print("3 - Apply SSH recommendations")
    print("4 - John The Ripper menu")
    print("5 - Quit")
    return input("Select an option (1-5): ")

# Function to display the analysis level options
def select_analysis_level():
    print("\n===== Select Analysis Level =====")
    print("1 - Global analysis")
    print("2 - Minimal analysis")
    print("3 - Intermediate analysis")
    print("4 - Enhanced analysis")
    print("5 - SSH configuration analysis only")
    print("6 - Return to main menu")
    return input("Select an option (1-6): ")

# Function to display the application level options
def select_application_level():
    print("\n===== Select Application Level =====")
    print("1 - Minimal application")
    print("2 - Manual application (GenerationRapport/RapportApplication/application.yml)")
    print("3 - Return to main menu")
    return input("Select an option (1-3): ")

# Main function of the script
def main():
    while True:
        menu_choice = display_main_menu()

        if menu_choice == "1":  # Run analysis
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

                print("\n--- Beginning analysis ---\n")

                # Run the analysis based on the user's choice
                if analysis_choice == "1":
                    print("\n[Analysis] Running global analysis...")
                    analyse_min(client)  # Example call (to be updated with the appropriate analysis functions)

                elif analysis_choice == "2":
                    print("\n[Analysis] Running minimal analysis...")
                    analyse_min(client)

                elif analysis_choice == "3":
                    print("\n[Analysis] Running intermediate analysis...")
                    analyse_moyen(client)

                elif analysis_choice == "4":
                    print("\n[Analysis] Running enhanced analysis...")
                    # Add the enhanced analysis function here (e.g., analyse_enhanced(client))

                elif analysis_choice == "5":
                    print("\n[Analysis] Running SSH configuration analysis only...")
                    analyse_SSH(client)

                # Close the connection after analysis
                client.close()
                print("\n--- Analysis completed ---\n")

            elif analysis_choice == "6":
                continue

        elif menu_choice == "2":  # Apply general recommendations
            print("\n--- Beginning application of general recommendations ---\n")
            
            application_choice = select_application_level()
            if application_choice == "1":
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

                Gui("GenerationRapport/RapportAnalyse/analyse_min.yml", "GenerationRapport/RapportApplication/application.yml")
                application_recommandations_min(client)

                # Close the connection after applying recommendations
                client.close()
                print("\n--- General recommendations applied ---\n")

            elif application_choice == "2":
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

                application_recommandations_min(client)

                # Close the connection after applying recommendations
                client.close()
                print("\n--- General recommendations applied ---\n")

            elif application_choice == "3":
                continue

        elif menu_choice == "3":  # Apply SSH recommendations
            print("\n--- Beginning application of SSH recommendations ---\n")

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
            apply_selected_recommendationsSSH("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml", client)

            # Close the connection after applying recommendations
            client.close()
            print("\n--- SSH recommendations applied ---\n")

        elif menu_choice == "4":  # John The Ripper menu
            print("\n--- Accessing John The Ripper menu ---\n")
            john.menu_principal()  # Call the menu from the john module

        elif menu_choice == "5":  # Quit
            print("Exiting the program...")
            sys.exit()

        else:
            print("Invalid option, please choose a correct option.")

# Entry point of the script
if __name__ == "__main__":
    main()
