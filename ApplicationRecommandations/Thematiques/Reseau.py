import yaml
import subprocess
import re

def extract_interface_name(entry):
    """Extrait uniquement le nom de l'interface à partir d'une entrée IP+interface"""
    match = re.search(r'%([^:]+)', entry)  # Capture l'interface après '%'
    return match.group(1) if match else None

def ask_for_approval(rule):
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def apply_recommandation_reseau_min(yaml_file, client):
    """Applique les recommandations de la règle R80 et met à jour le fichier YAML si tout est appliqué avec succès."""
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get('R80', {})
    
    if rule_data.get('appliquer', False):
        print("La règle R80 est déjà appliquée.")
        return

    interfaces_non_utilisees_udp = rule_data.get('interfaces_non_utilisees_udp', [])
    interfaces_non_utilisees_tcp = rule_data.get('interfaces_non_utilisees_tcp', [])

    print("Interfaces non utilisées à bloquer (UDP) :", interfaces_non_utilisees_udp)
    print("Interfaces non utilisées à bloquer (TCP) :", interfaces_non_utilisees_tcp)

    if not ask_for_approval("R80"):
        print("La règle R80 ne sera pas appliquée.")
        return

    all_rules_applied = True  

    try:
        # Blocage des interfaces UDP
        for entry in interfaces_non_utilisees_udp:
            interface = extract_interface_name(entry)
            
            if interface:
                confirmation = input(f"Bloquer l'interface {interface} pour UDP ? (o/n) ").strip().lower()
                if confirmation == 'o':
                    command = f"sudo iptables -A INPUT -i {interface} -j DROP"
                    stdin, stdout, stderr = client.exec_command(command)

                    error = stderr.read().decode()
                    if error:
                        print(f"Échec du blocage de {interface} pour UDP : {error}")
                        all_rules_applied = False
                    else:
                        print(f"Interface {interface} bloquée pour UDP.")
            else:
                print(f"Ignoré : {entry} (entrée invalide)")

        # Blocage des interfaces TCP
        for entry in interfaces_non_utilisees_tcp:
            interface = extract_interface_name(entry)
            
            if interface:
                confirmation = input(f"Bloquer l'interface {interface} pour TCP ? (o/n) ").strip().lower()
                if confirmation == 'o':
                    command = f"sudo iptables -A INPUT -i {interface} -j DROP"
                    stdin, stdout, stderr = client.exec_command(command)

                    error = stderr.read().decode()
                    if error:
                        print(f"Échec du blocage de {interface} pour TCP : {error}")
                        all_rules_applied = False
                    else:
                        print(f"Interface {interface} bloquée pour TCP.")
            else:
                print(f"Ignoré : {entry} (entrée invalide)")

        if all_rules_applied:
            rule_data['status'] = 'Conforme'
            rule_data['appliquer'] = True
            rule_data['interfaces_non_utilisees_udp'] = []
            rule_data['interfaces_non_utilisees_tcp'] = []
            data['R80'] = rule_data

            with open(yaml_file, 'w', encoding="utf-8") as file:
                yaml.dump(data, file, default_flow_style=False, allow_unicode=True)

            print("Le fichier YAML a été mis à jour avec succès.")
            client.exec_command("echo 'R80 - Recommandations appliquées et fichier YAML mis à jour.'")

    except Exception as e:
        print(f"Erreur lors de l'application des règles R80 : {e}")
        client.exec_command(f"echo 'Erreur lors de l'application de la règle R80 : {e}'")
