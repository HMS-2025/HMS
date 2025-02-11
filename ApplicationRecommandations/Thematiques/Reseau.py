import yaml
import subprocess

def ask_for_approval(rule):
    """Demande l'approbation de l'utilisateur pour appliquer une règle."""
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def apply_recommandation_reseau_min(yaml_file, client):
    """Applique les recommandations de la règle R80 en fonction des interfaces détectées
    et met à jour le fichier YAML avec les nouvelles informations."""
    
    # Charger le fichier YAML
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    # Récupérer la règle R80
    rule_data = data.get('80', {})
    
    # Vérifier si la règle doit être appliquée (appliquer == False)
    if rule_data.get('appliquer', False):
        print("La règle R80 est déjà appliquée.")
        return

    # Interfaces détectées et non utilisées
    interfaces_detectees = rule_data.get('interfaces_detectees', [])
    interfaces_non_utilisees_tcp = rule_data.get('interfaces_non_utilisees_tcp', [])
    interfaces_non_utilisees_udp = rule_data.get('interfaces_non_utilisees_udp', [])
    interfaces_utilisees_tcp = rule_data.get('interfaces_utilisees_tcp', [])
    interfaces_utilisees_udp = rule_data.get('interfaces_utilisees_udp', [])

    # Description des éléments attendus
    print("Description des éléments détectés dans R80 :")
    print(f"Interfaces détectées : {interfaces_detectees}")
    print(f"Interfaces non utilisées (TCP) : {interfaces_non_utilisees_tcp}")
    print(f"Interfaces non utilisées (UDP) : {interfaces_non_utilisees_udp}")

    # Liste des interfaces attendues
    expected_interfaces = [
        "192.168.1.0/24",
        "10.0.0.0/24",
        "127.0.0.1",
        "::1",
        "fe80::/10",
        "127.0.0.53%lo",
        "127.0.0.54",
        "localhost"
    ]

    # Appliquer les recommandations
    print("Applique les recommandations de sécurité :")
    print("Restriction des interfaces non utilisées...")

    # Demander l'approbation avant d'appliquer les règles
    if not ask_for_approval("R80"):
        print("La règle R80 ne sera pas appliquée.")
        return

    # Liste des interfaces non utilisées pour le TCP et UDP
    try:
        # Exemple de commande pour bloquer les interfaces non utilisées TCP
        for interface in interfaces_non_utilisees_tcp:
            confirmation = input(f"Souhaitez-vous bloquer l'interface TCP non utilisée {interface} ? (o/n) ").strip().lower()
            if confirmation == 'o':
                subprocess.run(['iptables', '-A', 'INPUT', '-i', interface, '-j', 'DROP'], check=True)
                print(f"Interface TCP non utilisée {interface} bloquée.")
            else:
                print(f"Interface TCP non utilisée {interface} non bloquée.")

        # Exemple de commande pour bloquer les interfaces non utilisées UDP
        for interface in interfaces_non_utilisees_udp:
            confirmation = input(f"Souhaitez-vous bloquer l'interface UDP non utilisée {interface} ? (o/n) ").strip().lower()
            if confirmation == 'o':
                subprocess.run(['iptables', '-A', 'INPUT', '-i', interface, '-j', 'DROP'], check=True)
                print(f"Interface UDP non utilisée {interface} bloquée.")
            else:
                print(f"Interface UDP non utilisée {interface} non bloquée.")
        
        print("Recommandations appliquées avec succès.")

        # Mise à jour du YAML avec les nouvelles données
        rule_data['status'] = 'Conforme'
        rule_data['appliquer'] = True
        rule_data['interfaces_non_utilisees_tcp'] = []
        rule_data['interfaces_non_utilisees_udp'] = []
        data['80'] = rule_data

        # Sauvegarder les modifications dans le fichier YAML
        with open(yaml_file, 'w', encoding="utf-8") as file:
            yaml.safe_dump(data, file)

        print(f"Le fichier YAML a été mis à jour avec succès.")

        # Retourner une réponse au client, ici on l'informe que les actions ont été appliquées
        client.send("R80 - Recommandations appliquées et fichier YAML mis à jour.")

    except Exception as e:
        print(f"Erreur lors de l'application des règles R80 : {e}")
        client.send(f"Erreur lors de l'application de la règle R80 : {e}")

#apply_recommandation_reseau_min(yaml_file_reseau_min, client)
