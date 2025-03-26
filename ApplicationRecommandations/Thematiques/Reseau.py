import yaml
import re
import subprocess
import os
import pyshark
import ipaddress
from collections import defaultdict

def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def extract_interface_name(entry):
    """Extracts only the interface name from an IP+interface entry."""
    match = re.search(r'%([^:]+)', entry)  # Captures the interface after '%'
    return match.group(1) if match else None

def list_interfaces(client):
    """Lists the network interfaces available on the remote server."""
    print("Retrieving available network interfaces...")
    try:
        stdin, stdout, stderr = client.exec_command("tcpdump -D")
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            print(f"Error: {error.strip()}")
            return []

        interfaces = output.strip().split("\n")
        cleaned_interfaces = [line.split('.')[1].strip().split(' ')[0] for line in interfaces]
        
        print("\nAvailable interfaces:")
        for i, interface in enumerate(cleaned_interfaces):
            print(f"{i + 1}. {interface}")
        return cleaned_interfaces

    except Exception as e:
        print(f"Error retrieving interfaces: {e}")
        return []
    
def capture_traffic(client, interface, duration, output_file):
    """
    Captures all incoming network traffic on a specific interface for a given duration on a remote machine via SSH.
    """
    print(f"Capturing traffic on interface {interface} for {duration} seconds (remote)...")
    try:
        command = f"rm {output_file}"
        stdin, stdout, stderr = client.exec_command(command)

        # Remote tcpdump command to capture traffic
        command = f"timeout {duration} tcpdump -i {interface} -w {output_file}"
        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.recv_exit_status()  # Wait for proper execution to finish

        # Check for potential errors
        error = stderr.read().decode()
        if error:
            print(f"Error during capture: {error.strip()}")
    except Exception as e:
        print(f"Error capturing traffic: {e}")

def download_pcap(client, remote_pcap_file, local_pcap_file):
    """Downloads the captured PCAP file from the remote server."""

    # Check if the local file already exists
    if os.path.exists(local_pcap_file):
        try:
            os.remove(local_pcap_file)  # Delete the file if it exists
        except Exception as e:
            print(f"Error deleting file {local_pcap_file}: {e}")
            return

    try:
        # Create an SFTP connection and download the file
        sftp = client.open_sftp()
        sftp.get(remote_pcap_file, local_pcap_file)
        sftp.close()
    except Exception as e:
        print(f"Error downloading file: {e}")

def get_open_ports(client):
    """
    Retrieves the list of open ports on the remote machine via SSH.
    """
    stdin, stdout, stderr = client.exec_command("ss -tuln")
    output = stdout.read().decode()
    error = stderr.read().decode()

    if error:
        print(f"Error retrieving open ports: {error}")
        return set()

    open_ports = set()
    for line in output.splitlines():
        if any(proto in line for proto in ['tcp', 'udp']):
            parts = line.split()
            if len(parts) >= 5:
                address = parts[4]
                if ':' in address:
                    port = address.split(':')[-1]
                    if port.isdigit():
                        open_ports.add(int(port))

    print(f"Open ports on the remote machine: {open_ports}")
    return open_ports

def analyze_pcap_and_generate_script(client, file_path):
    """
    Analyzes a PCAP file and generates an IPTABLES script
    only for open ports detected on the remote machine.
    """
    open_ports = get_open_ports(client)
    cap = pyshark.FileCapture(file_path)
    traffic_summary = {}
    source_ports_to_allow = set()

    print("Analysis in progress...")

    try:
        for packet in cap:
            if 'IP' in packet:
                protocol = packet.transport_layer  # TCP/UDP
                src_port = packet[packet.transport_layer].srcport if hasattr(packet[packet.transport_layer], 'srcport') else None

                if src_port is not None:
                    src_port = int(src_port)
                    if src_port in open_ports:
                        source_ports_to_allow.add((protocol, src_port))

                key = f"Protocol: {protocol}, Source Port: {src_port}"
                traffic_summary[key] = traffic_summary.get(key, 0) + 1
    except Exception as e:
        print(f"Error while analyzing the PCAP file: {e}")
    finally:
        cap.close()

    # Display the summary

    print("\nSummary of analyzed traffic (filtered for open ports):")
    for key, count in traffic_summary.items():
        print(f"{key}: {count} packets")

    # Execute the IPTABLES rules
    execute_iptables_commands(client, source_ports_to_allow)

def execute_iptables_commands(client, source_ports_to_allow):
    """
    Executes IPTABLES commands on the remote server to allow traffic
    on specific ports, includes specific rules for port 22, and
    implements security-enhancing features. Allows the user to add
    additional source IP addresses and networks for port 22 manually.
    """
    try:
        # Step 1: Backup existing rules
        backup_file = "/tmp/iptables-backup.rules"

        print(f"Backing up current IPTABLES rules to {backup_file}...")
        stdin, stdout, stderr = client.exec_command(f"iptables-save > {backup_file}")
        error = stderr.read().decode()
        if error:
            print(f"Error while backing up current rules: {error.strip()}")

        # Step 2: Check if port 22 (SSH) is included in source_ports_to_allow
        authorised_sources = []
        if ('TCP', 22) in source_ports_to_allow:
            stdin, stdout, stderr = client.exec_command(
                "last -i | awk '{print $3}' | sort | uniq | grep -E '[0-9]{1,3}(\.[0-9]{1,3}){3}'"
            )
            last_ips = stdout.read().decode().splitlines()

            if not last_ips:
                source_ports_to_allow.remove(('TCP', 22))  # Remove port 22 if no IP is detected
            else:
                print("Sources address detected :")
                for ip in last_ips:
                    print(f"- {ip}")

                # Automatically add detected IPs as sources
                network_dict = defaultdict(list)
                for ip in last_ips:
                    try:
                        ip_network = ipaddress.IPv4Interface(ip + '/24').network
                        network_dict[ip_network].append(ip)
                    except ValueError:
                        print(f"Invalid IP address ignored: {ip}")

                # Prepare the IPs and subnets to allow
                for network, ips in network_dict.items():
                    if len(ips) > 1:  # Multiple IPs in the network -> Add the /24 network
                        authorised_sources.append(str(network))
                    else:  # Single IP in the network -> Add the individual IP
                        authorised_sources.append(ips[0])

                # Step 2.1: Ask the user if they want to add more IPs or networks
                while True : 
                    additional_sources = input("Do you want to add more IP addresses or networks for port 22? (yes/no): ").strip().lower()
                    if additional_sources == "yes":
                        while True:
                            new_source = input("Enter an IP address or network in CIDR format (or press Enter to finish): ").strip()
                            if not new_source:
                                break
                            try:
                                # Validate the IP or network
                                if "/" in new_source : 
                                    ip_network = ipaddress.IPv4Network(new_source, strict=False)
                                    authorised_sources.append(str(ip_network))
                                    print(f"\nSource {new_source} added.\n")
                                else :  
                                    ip = ipaddress.IPv4Address(new_source)
                                    authorised_sources.append(str(ip))
                                    print(f"\nSource {new_source} added.\n") 
                            except ValueError:
                                print(f"Invalid IP address or network: {new_source}")
                    elif additional_sources == 'no' : 
                        break
                    else : 
                        print("Invalid option")

        # Step 3: Reset and define basic IPTABLES rules
        commands = [
            "iptables -F",  # Reset rules
            "iptables -X",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        ]
        # Step 3.1: Display the list of currently allowed ports
        if source_ports_to_allow:
            print("\nCurrently allowed ports:")
            for protocol, port in source_ports_to_allow:
                print(f"- Protocol: {protocol}, Port: {port}")
        else:
            print("\nNo ports are currently allowed.")

        add_ports = input("Do you want to authorize additional ports? (yes/no): ").strip().lower()
        if add_ports == "yes":
            while True:
                try:
                    print("Enter 'exit' at any time to leave this process.")
                    protocol = input("Enter the protocol (TCP/UDP) for the port: ").strip().upper()
                    if protocol == "EXIT":
                        print("Exiting the port addition process.")
                        break
                    if protocol not in ["TCP", "UDP"]:
                        print("Invalid protocol. Please enter TCP or UDP.")
                        continue

                    port = input("Enter the port number (or press Enter to finish): ").strip()
                    if not port:
                        break
                    if port.lower() == "exit":
                        print("Exiting the port addition process.")
                        break

                    if port.isdigit() and 1 <= int(port) <= 65535:
                        source_ports_to_allow.add((protocol, int(port)))
                        print(f"Port {port}/{protocol} added to the list of allowed ports.")
                    else:
                        print("Invalid port number. Please enter a number between 1 and 65535.")
                except ValueError:
                    print("Invalid input. Please try again.")


        # Step 4: Add specific rules for each protocol and port
        for protocol, port in source_ports_to_allow:
            if port == 22:  # Specific rules for port 22
                for source in authorised_sources:
                    commands.append(f"iptables -A INPUT -p {protocol.lower()} --dport {port} -s {source} -j ACCEPT")
            elif port == 80:  # HTTP port
                commands.append(f"iptables -A INPUT -p tcp --dport {port} -m conntrack --ctstate NEW -j ACCEPT")
                commands.append(f"iptables -A INPUT -p tcp --dport {port} -m limit --limit 50/min --limit-burst 100 -j ACCEPT")
            elif port == 443:  # HTTPS port
                commands.append(f"iptables -A INPUT -p tcp --dport {port} -m conntrack --ctstate NEW -j ACCEPT")
                commands.append(f"iptables -A INPUT -p tcp --dport {port} -m limit --limit 100/min --limit-burst 200 -j ACCEPT")
            else:  # General rules for other ports
                commands.append(f"iptables -A INPUT -p {protocol.lower()} --dport {port} -j ACCEPT")

            # Step 5: Implement connection limits to prevent DDoS attacks
            commands.append(
                f"iptables -A INPUT -p {protocol.lower()} --dport {port} -m connlimit --connlimit-above 10 -j REJECT"
            )

        # Step 6: Enable logging for dropped packets for analysis
        commands.append("iptables -A INPUT -j LOG --log-prefix 'IPTABLES DROPPED: '")

        # Step 7: Create the IPTABLES script
        iptable_script = "/root/iptables_authorize.sh"
        print(f"Creating the script {iptable_script}...")

        # Define the blocklist sources
        blocklists = [
            "https://lists.blocklist.de/lists/all.txt",  # Blocklist.de
        ]

        # Prompt the user
        add_blocklist = input("Do you want to block malicious IP addresses using external sources? (yes/no): ").strip().lower()
        if add_blocklist == "yes":
            # Inform the user about the sources
            print("\nThe following sources will be used to retrieve malicious IP addresses:")
            for url in blocklists:
                print(f"- {url}")
            
            confirm_download = input("\nDo you want to proceed with downloading and blocking these IPs? (yes/no): ").strip().lower()
            if confirm_download == "yes":
                # Remove any existing blacklist file to start fresh
                print("Removing any existing blacklist file from /root/blacklist.txt...")
                stdin, stdout, stderr = client.exec_command("rm -f /root/blacklist.txt")
                stdout.channel.recv_exit_status()  # Wait for the command to complete
                
                # Handle errors in removal
                error = stderr.read().decode().strip()
                if error:
                    print(f"Error while removing existing blacklist file: {error}")

                # Download blocklists to the server
                for url in blocklists:
                    print(f"Downloading blocklist from {url}...")
                    stdin, stdout, stderr = client.exec_command(f"curl -s {url} >> /root/blacklist.txt")
                    stdout.channel.recv_exit_status()  # Wait for the download to complete
                    
                    # Handle errors in download
                    error = stderr.read().decode().strip()
                    if error:
                        print(f"Error downloading blocklist from {url}: {error}")
                        continue

                print("Downloaded and consolidated blocklists into /root/blacklist.txt.")
                
                # Add the script for processing the blocklist and injecting IPs into iptables
                commands.append(
                    """
if [[ -f /root/blacklist.txt ]]; then
        while IFS= read -r ip; do
                echo 'Blocking and logging for: \$ip'
                iptables -w -A INPUT -s \$ip -j DROP
        done < <(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]{1,2}))?' /root/blacklist.txt | sort -u)
else
    echo Blacklist file not found. Skipping IP blocking.
fi
                    """
                )
                print("Added malicious IP blocking rules to the iptables script.")
            else:
                print("Aborted malicious IP blocking process.")
        else:
            print("Skipping malicious IP blocking.")

      
        stdin, stdout, stderr = client.exec_command(f"echo '#!/bin/bash' > {iptable_script}")
        stdin, stdout, stderr = client.exec_command(f"chmod u+x {iptable_script}")
        for command in commands:
            client.exec_command(f"echo \"{command}\" >> {iptable_script}")

        # Display the generated script
        print("\nGenerated IPTABLES script content:\n")
        stdin, stdout, stderr = client.exec_command(f"cat {iptable_script}")
        script_content = stdout.read().decode()
        print(script_content)

        # Step 8: Confirm execution of the script
        print("\n Downloading iptables script  \n")
        download_pcap(client , iptable_script , './iptables.sh')
        download_pcap(client , '/root/blacklist.txt' , './blacklist.txt' )
        
        execute_script = input("Do you want to execute this script to apply the new rules? (yes/no): ").strip().lower()
        if execute_script == "yes":
            print("Applying the new IPTABLES rules...")
            stdin, stdout, stderr = client.exec_command(f"bash {iptable_script}")
            output = stdout.read().decode()
            error = stderr.read().decode()
            if error:
                print(f"Error while applying the new rules: {error.strip()}")
            else:
                print("New rules successfully applied.")
        else:
            print("Execution canceled by the user.")

    except Exception as e:
        print(f"Error: {e}")


def iptables(client, yaml_file):
    """
    Main function to capture network traffic, download the PCAP file,
    and generate an IPTABLES script based on the analyzed data.
    """

    # List network interfaces on the remote machine
    interfaces = list_interfaces(client)
    if not interfaces:
        print("No interfaces available. Please check the remote configuration.")
        return

    # Ask the user to select an interface
    try:
        choice = int(input("\nSelect an interface (number): ")) - 1
        if 0 <= choice < len(interfaces):
            selected_interface = interfaces[choice]
            print(f"Selected interface: {selected_interface}")
        else:
            print("Invalid choice. Please try again.")
            return
    except ValueError:
        print("Invalid input. Please enter a number.")
        return

    # Ask the user for the listening duration
    try:
        capture_duration = int(input("\nEnter the listening duration in seconds: "))
        if capture_duration <= 0:
            print("Please enter a valid duration (greater than 0).")
            return
    except ValueError:
        print("Invalid input. Please enter a positive integer for the duration.")
        return

    # Configuration for remote capture
    output_file = "/tmp/captured_traffic.pcap"  # Remote path
    local_pcap_file = "/tmp/captured_traffic.pcap"  # Local path

    # Start the capture
    capture_traffic(client, selected_interface, capture_duration, output_file)
    download_pcap(client, output_file, local_pcap_file)

    # Analyze the PCAP file and generate the .sh script
    analyze_pcap_and_generate_script(client, local_pcap_file)


def apply_rule(rule_name, yaml_file, client , level):
    if level =='min' : 
        if rule_name == "R80":
            iptables(client , yaml_file)
        else:
            print(f"Règle inconnue:{rule_name}")
    elif level == "moyen": 
        pass
    else : 
        pass
def apply_recommandation_reseau(yaml_file, client , level):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)  
        if not data or 'network' not in data:
            return
        for rule, rule_data in data['network'].items():
            if not rule_data.get('apply', False):
                print(f"Règle {rule} déjà appliquée.")
            else:
                apply_rule(rule, yaml_file, client , level)
                
    except FileNotFoundError:
        print(f"Fichier {yaml_file} non trouvé.")
    except yaml.YAMLError as e:
        print(f"Erreur lors de la lecture du fichier YAML : {e}")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite : {e}")

######----------------------------------------PARTIE moyen--------------------------------------------------------------------------------------------------######

import os
#from ApplicationRecommandations.execute_command import execute_ssh_command # import non correcte
##Ajout  de la fonction immediatement mais à enlever par la suite pour l'importer

def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# ============================
# Fonction utilitaire commune
# ============================

def save_yaml_fix_report_reseau(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportCorrections"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("corrections:\n")

        for rule_id, status in data.items():
            for thematique, niveaux in rules.items():
                if niveau in niveaux and rule_id in niveaux[niveau]:
                    comment = niveaux[niveau][rule_id][1]
                    file.write(f"  {rule_id}:  # {comment} ({thematique})\n")
                    file.write(f"    status: {status}\n")

    print(f"✅ Rapport des corrections RESEAU généré : {output_path}")

# ============================
# RÈGLES RESEAU
# ============================

def apply_r12(serveur, report):
    r12_data = report.get("reseau", {}).get("R12", {})
    if not r12_data.get("apply", False):
        print("✅ R12 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R12 : Configuration IPv4...")

    ipv4_params = r12_data.get("expected_elements", {})
    if not ipv4_params:
        print("⚠️  R12 : Paramètres manquants !")
        return "Erreur : Paramètres manquants"

    execute_ssh_command(serveur, "sudo cp -n /etc/sysctl.conf /etc/sysctl.conf.HMS.bak")

    for param, value in ipv4_params.items():
        print(f"➡️  Application de {param} = {value}")
        execute_ssh_command(serveur, f"sudo sysctl -w {param}={value}")
        execute_ssh_command(serveur, f"sudo sed -i '/^{param}/d' /etc/sysctl.conf")
        execute_ssh_command(serveur, f"echo '{param} = {value}' | sudo tee -a /etc/sysctl.conf > /dev/null")

    execute_ssh_command(serveur, "sudo sysctl -p")
    print("✅ R12 : Paramètres IPv4 appliqués.")
    return "Appliqué"

def apply_r13(serveur, report):
    r13_data = report.get("reseau", {}).get("R13", {})
    if not r13_data.get("apply", False):
        print("✅ R13 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R13 : Désactivation IPv6...")

    ipv6_disable_params = {
        "net.ipv6.conf.all.disable_ipv6": "1",
        "net.ipv6.conf.default.disable_ipv6": "1",
        "net.ipv6.conf.lo.disable_ipv6": "1"
    }

    execute_ssh_command(serveur, "sudo cp -n /etc/sysctl.conf /etc/sysctl.conf.HMS.bak")

    for param, value in ipv6_disable_params.items():
        execute_ssh_command(serveur, f"sudo sysctl -w {param}={value}")
        execute_ssh_command(serveur, f"sudo sed -i '/^{param}/d' /etc/sysctl.conf")
        execute_ssh_command(serveur, f"echo '{param} = {value}' | sudo tee -a /etc/sysctl.conf > /dev/null")

    execute_ssh_command(serveur, "sudo sysctl -p")
    print("✅ R13 : IPv6 désactivé.")
    return "Appliqué"

def apply_r67(serveur, report):
    r67_data = report.get("reseau", {}).get("R67", {})
    if not r67_data.get("apply", False):
        print("✅ R67 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R67 : Sécurisation de l'authentification distante PAM...")

    expected_rules = r67_data.get("expected_elements", {}).get("pam_rules", [])
    detected_rules = r67_data.get("detected_elements", {}).get("pam_rules", [])

    if not expected_rules:
        print("❌ R67 : Aucune règle PAM attendue trouvée dans le rapport !")
        return "Erreur : données manquantes"

    pam_files = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-account",
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-session"
    ]

    for pam_file in pam_files:
        execute_ssh_command(serveur, f"sudo cp -n {pam_file} {pam_file}.HMS.bak")

    missing_rules = [rule for rule in expected_rules if rule not in detected_rules]

    if not missing_rules:
        print("✅ R67 : Toutes les règles PAM attendues sont déjà en place.")
        return "Conforme"

    print(f"➡️ R67 : Ajout des règles manquantes : {len(missing_rules)}")

    for rule in missing_rules:
        execute_ssh_command(serveur, f"echo '{rule}' | sudo tee -a /etc/pam.d/common-auth > /dev/null")

    print("✅ R67 : Règles PAM ajoutées avec succès.")
    return "Appliqué"

def apply_r79(serveur, report):
    r79_data = report.get("reseau", {}).get("R79", {})
    if not r79_data.get("apply", False):
        print("✅ R79 : Aucune action nécessaire.")
        return "Conforme"

    services_to_harden = r79_data.get("detected_elements", {}).get("running_services", [])

    if not services_to_harden:
        print("✅ R79 : Aucun service exposé détecté.")
        return "Conforme"

    print("🔧 Application de la règle R79 : Durcissement des services exposés...")

    for service in services_to_harden:
        print(f"➡️  Restriction du service {service}")
        execute_ssh_command(serveur, f"sudo systemctl disable {service}")
        execute_ssh_command(serveur, f"sudo systemctl stop {service}")

    print("✅ R79 : Services exposés désactivés.")
    return "Appliqué"

def apply_r81(serveur, report):
    r81_data = report.get("reseau", {}).get("R81", {})
    if not r81_data.get("apply", False):
        print("✅ R81 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R81 : Vérification des interfaces restreintes...")

    interfaces = r81_data.get("detected_elements", {})

    for iface, ip_info in interfaces.items():
        print(f"➡️ Interface {iface} : IPv4={ip_info.get('ipv4')} IPv6={ip_info.get('ipv6')}")

    print("✅ R81 : Interfaces réseau restreintes vérifiées.")
    return "Appliqué"






#######################################################################################
#                                                                                     #
#                        Gestion d'acces niveau renforcé                              #
#                                                                                     #
#######################################################################################

#Nous lui affichons de la commande deplacement de ces services reseau, car les deplacer automatiquement reste crtique pour le bon fonctionnement de son systeme complet
def apply_R78(serveur, report):
    """
    Applies rule R78 by checking if network services are distributed into distinct slices.
    Ensures no slice contains 50% or more of the services.
    If the slice contains too many services, it suggests corrective actions.
    """
    
    r78_data = report.get("network", {}).get("R78", {})
    
    if not r78_data.get("apply", False):
        print("- R78: No action required.")
        return "Compliant"

    print("\n    Applying rule R78 (Isolate network services)    \n")
    
    detected_slices = r78_data.get("detected_elements", {})
    
    if not detected_slices:
        print("⚠️ No detected slices found.")
        return "Failed"

    # Calcul du nombre total de services détectés
    total_services = sum(len(services) for services in detected_slices.values())

    print("🔍 Detected slices and services:")
    for slice_name, services in detected_slices.items():
        print(f"  - Slice: {slice_name} (Contains {len(services)} services)")
        for service in services:
            print(f"    - {service}")

    # Vérifier si une tranche contient 50% ou plus des services
    threshold = total_services / 2
    problematic_slices = []

    for slice_name, services in detected_slices.items():
        if len(services) >= threshold:
            problematic_slices.append(slice_name)

    if problematic_slices:
        print("\n⚠️ The following slices contain 50% or more of the services:")
        for slice_name in problematic_slices:
            print(f"  - {slice_name} (Contains {len(detected_slices[slice_name])} services)")

        # Suggest corrective action
        print("\n🔧 For manually moving, execute : sudo systemctl set-property <service_name> Slice=<target_slice>")
        input("\nPress Enter to continue...")
        return "Non-Compliant"

    else:
        print("✅ Rule R78 applied successfully. All services are correctly distributed into distinct slices.")
        return "Compliant"


################ Fin niveau renforce #######################


# ============================
# FONCTION PRINCIPALE RESEAU
# ============================

def apply_reseau(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    fix_results = {}

    rules = {
        "reseau": {
            "moyen": {
                "R12": (apply_r12, "Paramétrer les options de configuration IPv4"),
                "R13": (apply_r13, "Désactiver le plan IPv6"),
                "R67": (apply_r67, "Sécuriser l'authentification distante par PAM"),
                "R79": (apply_r79, "Durcir et surveiller les services exposés"),
                "R81": (apply_r81, "Restreindre les interfaces réseau")
            },
            "renforce": {
                "R71": (apply_R78, "Isolate network services: verify services are distributed into distinct slices")
            }
        }
    }

    if niveau in rules["reseau"]:
        for rule_id, (function, comment) in rules["reseau"][niveau].items():
            print(f"-> Application de la règle {rule_id} : {comment}")
            fix_results[rule_id] = function(serveur, report_data)

    output_file = f"fixes_{niveau}_reseau.yml"
    save_yaml_fix_report_reseau(fix_results, output_file, rules, niveau)

    print(f"\n✅ Correctifs appliqués - RESEAU - Niveau {niveau.upper()} : {output_file}")
    return fix_results
