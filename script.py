import argparse
import sys
from Config import load_config, ssh_connect
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min, analyse_moyen, analyse_renforce
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendationsSSH
from ApplicationRecommandations.AppRecommandationsMin import application_recommandations_min
from gui import Gui
import john  # Module for John The Ripper

def print_remote_os_version():
    """
    Connects to the remote server via SSH and prints the OS version.
    If the remote OS is Ubuntu 20.04, prints "You are using Ubuntu 20.04".
    Otherwise, prints "Not supported".
    """
    config = load_config("ssh.yaml")
    if not config:
        print("Invalid configuration for OS version check")
        return

    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )
    if not client:
        print("SSH connection failed for OS version check")
        return

    try:
        stdin, stdout, stderr = client.exec_command("cat /etc/os-release")
        output = stdout.read().decode("utf-8")
        distro = None
        version = None
        for line in output.splitlines():
            if line.startswith("ID="):
                distro = line.split("=")[1].strip().strip('"')
            elif line.startswith("VERSION_ID="):
                version = line.split("=")[1].strip().strip('"')
        if distro and distro.lower() == "ubuntu" and version == "20.04":
            print(f"You are using Ubuntu {version}")
        else:
            print("Not supported")
    except Exception as e:
        print("Error reading remote OS version:", e)
    finally:
        client.close()

def check_remote_os_support(client):
    """
    Checks the remote server's OS via SSH.
    If the remote server is running Ubuntu 20.04, prints that it is supported.
    Otherwise, prints that the remote OS is not supported.
    """
    try:
        stdin, stdout, stderr = client.exec_command("cat /etc/os-release")
        output = stdout.read().decode("utf-8")
        distro = None
        version = None
        for line in output.splitlines():
            if line.startswith("ID="):
                distro = line.split("=")[1].strip().strip('"')
            elif line.startswith("VERSION_ID="):
                version = line.split("=")[1].strip().strip('"')
        if distro and distro.lower() == "ubuntu" and version == "20.04":
            print(f"Remote server is using Ubuntu {version} - Supported")
            return True
        else:
            print("Remote server OS not supported")
            return False
    except Exception as e:
        print("Error checking remote OS:", e)
        return False

def run_analysis(mode):
    # Load SSH configuration
    config = load_config("ssh.yaml")
    if not config:
        print("Invalid configuration")
        return

    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )
    if not client:
        print("SSH connection failed")
        return

    # Check remote OS support before running the analysis
    check_remote_os_support(client)

    print("\n--- Starting Analysis ---\n")
    if mode == "minimal":
        print("[Analysis] Running minimal analysis...")
        analyse_min(client)
    elif mode == "intermediate":
        print("[Analysis] Running intermediate analysis...")
        analyse_moyen(client)
    elif mode == "reinforced":
        print("[Analysis] Running reinforced analysis...")
        analyse_renforce(client)
    elif mode == "all":
        print("[Analysis] Running all scans...")
        analyse_min(client)
        analyse_moyen(client)
        analyse_renforce(client)
    elif mode == "all":
        print("[Analysis] Running all scans...")
        analyse_min(client)
        analyse_moyen(client)
    elif mode == "ssh":
        print("[Analysis] Running SSH analysis only...")
        analyse_SSH(client)

    client.close()
    print("\n--- Analysis Completed ---\n")

def run_recommendations(app_type):
    config = load_config("ssh.yaml")
    if not config:
        print("Invalid configuration")
        return

    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )
    if not client:
        print("SSH connection failed")
        return

    if app_type == "general":
        print("\n--- Applying General Recommendations ---\n")
        Gui("GenerationRapport/RapportAnalyse/analyse_min.yml", "GenerationRapport/RapportApplication/application.yml")
        application_recommandations_min(client)
    elif app_type == "ssh":
        print("\n--- Applying SSH Recommendations ---\n")
        apply_selected_recommendationsSSH("GenerationRapport/RapportAnalyse/ssh_compliance_report.yaml", client)

    client.close()
    print("\n--- Recommendations Applied ---\n")

def interactive_menu():
    # Basic interactive menu
    while True:
        print("\n===== Main Menu =====")
        print("1 - Run Analysis")
        print("2 - Apply General Recommendations")
        print("3 - Apply SSH Recommendations")
        print("4 - John The Ripper Menu")
        print("5 - Exit")
        choice = input("Select an option (1-5): ")

        if choice == "1":
            while True:
                print("\n===== Select Analysis Level =====")
                print("1 - Global Analysis")
                print("2 - Minimal Analysis")
                print("3 - Intermediate Analysis")
                print("4 - Enhanced Analysis")
                print("5 - SSH Config Analysis Only")
                print("6 - Back")
                sub_choice = input("Select an option (1-6): ")
                if sub_choice == "1":
                    run_analysis("all")
                elif sub_choice == "2":
                    run_analysis("minimal")
                elif sub_choice == "3":
                    run_analysis("intermediate")
                elif sub_choice == "4":
                    run_analysis("reinforced")
                elif sub_choice == "5":
                    run_analysis("ssh")
                elif sub_choice == "6":
                    break
                else:
                    print("Invalid option, please try again.")
        elif choice == "2":
            run_recommendations("general")
        elif choice == "3":
            run_recommendations("ssh")
        elif choice == "4":
            print("\n--- John The Ripper Menu ---\n")
            john.menu_principal()
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid option, please try again.")


def main():
    # Print the remote OS version when the script is launched
    print_remote_os_version()

    parser = argparse.ArgumentParser(description="Analysis and Recommendations Script")
    parser.add_argument("-m", "--minimal", action="store_true", help="Run minimal analysis")
    parser.add_argument("-i", "--intermediate", action="store_true", help="Run intermediate analysis")
    parser.add_argument("-rf", "--reinforced", action="store_true", help="Run enhanced analysis")
    parser.add_argument("-ssh", "--ssh", action="store_true", help="Run SSH analysis only")
    parser.add_argument("-all", "--all", action="store_true", help="Run all scans")
    parser.add_argument("-r", "--recommendations", choices=["general", "ssh"], help="Apply recommendations: 'general' or 'ssh'")
    args = parser.parse_args()

    analysis_flags = []

    if args.all:
        analysis_flags = ["minimal", "intermediate", "reinforced", "ssh"]
    else:
        analysis_flags = []
        if args.minimal:
            analysis_flags.append("minimal")
        if args.intermediate:
            analysis_flags.append("intermediate")
        if args.reinforced:
            analysis_flags.append("reinforced")
        if args.ssh:
            analysis_flags.append("ssh")
        
        # Combine minimal and intermediate into all if both specified
        if {"minimal", "intermediate", "reinforced"}.issubset(set(analysis_flags)):
            analysis_flags = ["all"]
        elif {"minimal", "intermediate"}.issubset(set(analysis_flags)):
            analysis_flags = [flag for flag in analysis_flags if flag not in ["minimal", "intermediate"]]
            analysis_flags.append("all")

    # If "--all" is specified, it runs all available analyses
    if args.all:
        analysis_flags = ["minimal", "intermediate", "reinforced", "ssh"]
    else:
        analysis_flags = analysis_flags

    # Run requested analyses
    for flag in analysis_flags:
        run_analysis(flag)

    # Run recommendations if requested
    if args.recommendations:
        run_recommendations(args.recommendations)

    # If no arguments provided, launch interactive menu
    if not (analysis_flags or args.recommendations):
        interactive_menu()

if __name__ == "__main__":
    main()

