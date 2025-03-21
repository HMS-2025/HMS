from Config import load_config, ssh_connect
from AnalyseConfiguration.Analyseur import analyse_SSH, analyse_min, analyse_moyen, analyse_renforce
from ApplicationRecommandations.AppRecommandationsSSH import apply_selected_recommendationsSSH
from ApplicationRecommandations.AppRecommandationsMin import application_recommandations_min
from ApplicationRecommandations.AppRecommandationsMoyen import application_recommandations_moyen
from ApplicationRecommandations.Thematiques.Reseau import iptables
from gui import Gui
import argparse
import sys
import os
import john 



def print_remote_os_version():
    config = load_config("ssh.yaml")
    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )

    if not config:
        print("Invalid configuration for OS version check")
        return
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
    config = load_config("ssh.yaml")
    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
        )
    # Load SSH configuration
    if not config:
        print("Invalid configuration")
        return
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
    elif mode == "ssh":
        print("[Analysis] Running SSH analysis only...")
        analyse_SSH(client)

    client.close()
    print("\n--- Analysis Completed ---\n")

def run_recommendations(app_type):
    config = load_config("ssh.yaml")
    client = ssh_connect(
        hostname=config.get("hostname"),
        port=config.get("port"),
        username=config.get("username"),
        key_path=config.get("key_path"),
        passphrase=config.get("passphrase")
    )
    if not config:
        print("Invalid configuration")
        return
    if not client:
        print("SSH connection failed")
        return

    if app_type == "min":
        print("\n--- Applying minimal Recommendations ---\n")
        Gui("GenerationRapport/RapportAnalyse/analyse_min.yml", "GenerationRapport/RapportApplication/application_min.yml")
        application_recommandations_min(client)
    
    elif app_type=="inter" : 
        print("\n--- Applying intermediate Recommendations ---\n")
        Gui("GenerationRapport/RapportAnalyse/analyse_moyen.yml", "GenerationRapport/RapportApplication/application_moyen.yml")
        application_recommandations_moyen(client)
    elif app_type=="Iptables" : 
        print("\n--- Applying iptables ---\n")
        iptables(client , 'test')
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
            while True:
                print("\n===== Select Application Level =====")
                print("1 - Minimal application")
                print("2 - Intermediate application")
                print("3 - Iptables")
                print("4 - Back")
                sub_choice = input("Select an option (1-3): ")
                if sub_choice == "1":
                    run_recommendations("min")
                if sub_choice == "2":
                    run_recommendations("inter")
                if sub_choice == "3":
                    run_recommendations("Iptables")
                elif sub_choice == "4":
                    break
                else : 
                    print("Invalid option, please try again.")
 
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

def generate_wordlist_with_input(input_str):
    """
    Generates a wordlist based on an input string (words separated by spaces).
    For any word containing ":", both parts are added.
    If the 'cassage' file exists, extracts usernames (before ":").
    Then, for each word, generates complete variants using john.generate_full_variants().
    The wordlist is saved in the file 'liste générée'.
    """
    words_raw = input_str.split()
    words = []
    for w in words_raw:
        if ":" in w:
            parts = w.split(":")
            words.append(parts[0])
            words.append(parts[1])
        else:
            words.append(w)
    cassage_path = os.path.join(os.getcwd(), "cassage")
    if os.path.exists(cassage_path):
        with open(cassage_path, "r") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    username = line.split(":")[0]
                    words.append(username)
    words = list(set(words))
    all_variants = set()
    for word in words:
        variants = john.generate_full_variants(word)
        all_variants.update(variants)
    output_file = os.path.join(os.getcwd(), "liste générée")
    try:
        with open(output_file, "w") as f:
            for variant in sorted(all_variants):
                f.write(variant + "\n")
        print(f"Wordlist generated with {len(all_variants)} entries in file '{output_file}'.")
    except Exception as e:
        print(f"Error writing the wordlist: {e}")

def run_john(args):
    """
    Executes John The Ripper actions in the following order (if the corresponding options are provided):
      1. Installation
      2. Retrieve the shadow file via SSH
      3. Generate a wordlist using the provided input (--john-wordlist)
      4. Crack using the generated wordlist
    """
    if args.john_install:
        print("\n[John] Installing John The Ripper...")
        john.install_john()

    if args.john_shadow:
        print("\n[John] Retrieving shadow file via SSH...")
        config = load_config("ssh.yaml")
        if not config:
            print("Invalid SSH configuration.")
        else:
            client = ssh_connect(
                hostname=config.get("hostname"),
                port=config.get("port"),
                username=config.get("username"),
                key_path=config.get("key_path"),
                passphrase=config.get("passphrase")
            )
            if client:
                local_shadow_path = os.path.join(os.getcwd(), "shadow")
                john.retrieve_hash_files(client, "/etc/shadow", local_shadow_path)
                cassage_path = os.path.join(os.getcwd(), "cassage")
                john.save_hashes_from_shadow(local_shadow_path, cassage_path)
                client.close()

    if args.john_wordlist:
        print("\n[John] Generating wordlist with input:", args.john_wordlist)
        generate_wordlist_with_input(args.john_wordlist)

    if args.john_crack:
        print("\n[John] Running cracking process using generated wordlist...")
        cassage_path = os.path.join(os.getcwd(), "cassage")
        if os.path.exists(cassage_path):
            john.run_john_generated(cassage_path)
        else:
            print("[John] The 'cassage' file does not exist. Please retrieve the shadow file first.")

def main():
    print_remote_os_version()

    parser = argparse.ArgumentParser(description="Analysis and Recommendations Script with John The Ripper integration")
    # Analysis options
    parser.add_argument("-m", "--minimal", action="store_true", help="Run minimal analysis")
    parser.add_argument("-i", "--intermediate", action="store_true", help="Run intermediate analysis")
    parser.add_argument("-rf", "--reinforced", action="store_true", help="Run enhanced analysis")
    parser.add_argument("-ssh", "--ssh", action="store_true", help="Run SSH analysis only")
    parser.add_argument("-all", "--all", action="store_true", help="Run all scans")
    parser.add_argument("-r", "--recommendations", choices=["general", "ssh"], help="Apply recommendations: 'general' or 'ssh'")
    # John options
    parser.add_argument("--john", action="store_true", help="Run John The Ripper functions")
    parser.add_argument("--john-install", action="store_true", help="Install John The Ripper")
    parser.add_argument("--john-shadow", action="store_true", help="Retrieve shadow file for John")
    parser.add_argument("--john-wordlist", type=str, help="Generate wordlist with provided input (e.g. 'mot1 mot2')")
    parser.add_argument("--john-crack", action="store_true", help="Crack passwords using John with the generated wordlist")
    
    args = parser.parse_args()

    analysis_flags = []
    if args.all:
        analysis_flags = ["minimal", "intermediate", "reinforced", "ssh"]
    else:
        if args.minimal:
            analysis_flags.append("minimal")
        if args.intermediate:
            analysis_flags.append("intermediate")
        if args.reinforced:
            analysis_flags.append("reinforced")
        if args.ssh:
            analysis_flags.append("ssh")
        if {"minimal", "intermediate", "reinforced"}.issubset(set(analysis_flags)):
            analysis_flags = ["all"]
        elif {"minimal", "intermediate"}.issubset(set(analysis_flags)):
            analysis_flags = [flag for flag in analysis_flags if flag not in ["minimal", "intermediate"]]
            analysis_flags.append("all")
    
    if args.all:
        analysis_flags = ["minimal", "intermediate", "reinforced", "ssh"]

    for flag in analysis_flags:
        run_analysis(flag)

    if args.recommendations:
        run_recommendations(args.recommendations)

    if args.john:
        run_john(args)

    if not (analysis_flags or args.recommendations or args.john):
        interactive_menu()

if __name__ == "__main__":
    main()
