import yaml
import re
import subprocess
import os
import pyshark

def extract_interface_name(entry):
    """Extrait uniquement le nom de l'interface à partir d'une entrée IP+interface"""
    match = re.search(r'%([^:]+)', entry)  # Capture l'interface après '%'
    return match.group(1) if match else None

def ask_for_approval(rule):
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def list_interfaces(client):
    """Liste les interfaces réseau disponibles sur le serveur distant."""
    print("Récupération des interfaces réseau disponibles...")
    try:
        stdin, stdout, stderr = client.exec_command("tcpdump -D")
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            print(f"Erreur : {error.strip()}")
            return []

        interfaces = output.strip().split("\n")
        cleaned_interfaces = [line.split('.')[1].strip().split(' ')[0] for line in interfaces]
        
        print("\nInterfaces disponibles :")
        for i, interface in enumerate(cleaned_interfaces):
            print(f"{i + 1}. {interface}")
        return cleaned_interfaces

    except Exception as e:
        print(f"Erreur lors de la récupération des interfaces : {e}")
        return []
    
def capture_traffic(client, interface, duration, output_file):
    """
    Capture tout le trafic réseau entrant sur une interface spécifique pendant une durée donnée sur une machine distante via SSH.
    """
    print(f"Capture du trafic sur l'interface {interface} pendant {duration} secondes (distant)...")
    try:

        command = f"rm {output_file}"
        stdin, stdout, stderr = client.exec_command(command)

        # Commande tcpdump distante pour capturer le trafic
        command = f"timeout {duration} tcpdump -i {interface} -w {output_file}"
        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.recv_exit_status()  # Attendre la fin de l'exécution proprement


        # Attendre la fin de l'exécution
        stdout.channel.recv_exit_status()

        # Vérifier les erreurs éventuelles
        error = stderr.read().decode()
        if error:
            print(f"Erreur durant la capture : {error.strip()}")
        else:
            print(f"Capture terminée. Fichier enregistré sous {output_file} sur la machine distante.")
    except Exception as e:
        print(f"Erreur lors de la capture du trafic : {e}")


def download_pcap(client, remote_pcap_file, local_pcap_file):
    """Télécharge le fichier PCAP capturé depuis le serveur distant."""
    print(f"Téléchargement du fichier PCAP depuis {remote_pcap_file} vers {local_pcap_file}...")

    # Vérifier si le fichier local existe déjà
    if os.path.exists(local_pcap_file):
        print(f"Le fichier {local_pcap_file} existe déjà. Suppression...")
        try:
            os.remove(local_pcap_file)  # Supprime le fichier s'il existe
            print(f"Fichier {local_pcap_file} supprimé avec succès.")
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier {local_pcap_file} : {e}")
            return

    try:
        # Créer une connexion SFTP et télécharger le fichier
        sftp = client.open_sftp()
        sftp.get(remote_pcap_file, local_pcap_file)
        sftp.close()
        print("Téléchargement terminé.")
    except Exception as e:
        print(f"Erreur durant le téléchargement : {e}")

def get_open_ports(client):
    """
    Récupère la liste des ports ouverts sur la machine distante via SSH.
    """
    stdin, stdout, stderr = client.exec_command("ss -tuln")
    output = stdout.read().decode()
    error = stderr.read().decode()

    if error:
        print(f"Erreur lors de la récupération des ports ouverts : {error}")
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
    print(f"Ports ouverts sur la machine distante : {open_ports}")
    return open_ports


def analyze_pcap_and_generate_script(client, file_path):
    """
    Analyse un fichier PCAP et génère un script IPTABLES uniquement
    pour les ports ouverts détectés sur la machine distante.
    """
    open_ports = get_open_ports(client)
    cap = pyshark.FileCapture(file_path)
    traffic_summary = {}
    source_ports_to_allow = set()

    print("Analyse en cours...")

    try:
        for packet in cap:
            if 'IP' in packet:
                protocol = packet.transport_layer  # TCP/UDP
                src_port = packet[packet.transport_layer].srcport if hasattr(packet[packet.transport_layer], 'srcport') else None

                if src_port is not None:
                    src_port = int(src_port)
                    if src_port in open_ports:
                        source_ports_to_allow.add((protocol, src_port))

                key = f"Protocole: {protocol}, Port source: {src_port}"
                traffic_summary[key] = traffic_summary.get(key, 0) + 1
    except Exception as e:
        print(f"Erreur lors de l'analyse du fichier PCAP : {e}")
    finally:
        cap.close()

    # Afficher le résumé
    print("\nRésumé du trafic analysé (filtré sur les ports ouverts) :")
    for key, count in traffic_summary.items():
        print(f"{key}: {count} paquets")

    # Execution des regles iptable IPTABLES
    execute_iptables_commands(client ,source_ports_to_allow)

def execute_iptables_commands(client, source_ports_to_allow):
    """
    Exécute directement les commandes IPTABLES sur le serveur distant
    pour autoriser le trafic entrant provenant des ports source spécifiés,
    après avoir effectué une sauvegarde des règles existantes.
    """
    try:
        # Générer un chemin de sauvegarde unique basé sur l'heure actuelle
        backup_file = f"/tmp/iptables-backup.rules"

        print(f"Sauvegarde des règles IPTABLES actuelles dans {backup_file}...")

        # Effectuer la sauvegarde des règles actuelles sur le serveur distant
        stdin, stdout, stderr = client.exec_command(f"iptables-save > {backup_file}")
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            print(f"Erreur lors de la sauvegarde des règles actuelles : {error.strip()}")
        else:
            print("Sauvegarde réussie.")

        # Réinitialiser les règles IPTABLES
        commands = [
            "iptables -F",
            "iptables -X",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT",
        ]

        # Ajouter les règles pour les ports source détectés
        for protocol, port in source_ports_to_allow:
            commands.append(f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT")

        # Créer et exécuter le script IPTABLES sur le serveur distant
        iptable = "/iptables.sh"

        print(f"Création du script {iptable}...")
        stdin, stdout, stderr = client.exec_command(f"echo '#!/bin/bash' > {iptable}")
        stdin, stdout, stderr = client.exec_command(f"chmod +x {iptable}")

        for command in commands:
            stdin, stdout, stderr = client.exec_command(f"echo {command} >> {iptable}")
            output = stdout.read().decode()
            error = stderr.read().decode()

            if error:
                print(f"Erreur lors de l'ajout de la commande : {error.strip()}")

        print("Exécution des nouvelles règles IPTABLES...")
        stdin, stdout, stderr = client.exec_command(f"bash {iptable}")
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            print(f"Erreur lors de l'exécution des nouvelles règles : {error.strip()}")
        else:
            print("Nouvelles règles appliquées avec succès.")

    except Exception as e:
        print(f"Erreur lors de l'exécution des commandes IPTABLES : {e}")

def apply_80(client):
    """
    Fonction principale pour capturer le trafic réseau, télécharger le fichier PCAP
    et générer un script IPTABLES en fonction des données analysées.
    """

    # Lister les interfaces réseau sur la machine distante
    interfaces = list_interfaces(client)
    if not interfaces:
        print("Aucune interface disponible. Veuillez vérifier la configuration distante.")
        return

    # Demander à l'utilisateur de choisir une interface
    try:
        choice = int(input("\nSélectionnez une interface (numéro) : ")) - 1
        if 0 <= choice < len(interfaces):
            selected_interface = interfaces[choice]
            print(f"Interface sélectionnée : {selected_interface}")
        else:
            print("Choix invalide. Veuillez réessayer.")
            return
    except ValueError:
        print("Entrée invalide. Veuillez entrer un numéro.")
        return

    # Demander à l'utilisateur la durée d'écoute
    try:
        capture_duration = int(input("\nEntrez la durée d'écoute en secondes : "))
        if capture_duration <= 0:
            print("Veuillez entrer une durée valide (supérieure à 0).")
            return
    except ValueError:
        print("Entrée invalide. Veuillez entrer un entier positif pour la durée.")
        return

    # Configuration pour la capture distante
    output_file = "/tmp/captured_traffic.pcap"  # Chemin distant
    local_pcap_file = "/tmp/captured_traffic.pcap"  # Chemin local

    # Lancer la capture
    capture_traffic(client, selected_interface, capture_duration, output_file)
    download_pcap(client, output_file, local_pcap_file)
    # Analyser le fichier PCAP et générer le fichier .sh
    analyze_pcap_and_generate_script(client, local_pcap_file)

def apply_rule(rule_name, yaml_file, client , level):
    if level =='min' : 
        if rule_name == "R80":
            apply_80(client)
        else:
            print(f"Règle inconnue : {rule_name}")
    elif level == "moyen" : 
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
            if rule_data.get('appliquer', False):
                print(f"Règle {rule} déjà appliquée.")
            else:
                apply_rule(rule, yaml_file, client , level)
                
    except FileNotFoundError:
        print(f"Fichier {yaml_file} non trouvé.")
    except yaml.YAMLError as e:
        print(f"Erreur lors de la lecture du fichier YAML : {e}")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite : {e}")