import subprocess
import os
import yaml

def ask_for_approval(rule):
    """Demander à l'utilisateur s'il souhaite appliquer la règle spécifiée."""
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def install_expected_elements(yaml_file, client):
    """Installer les éléments attendus s'ils ne sont pas déjà installés."""
    elements_installes = []

    # Charger le fichier YAML pour récupérer les éléments attendus
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    rule_data = data.get("R61", {})
    elements_attendus = rule_data.get('éléments_attendus', {})

    for element, valeur in elements_attendus.items():
        if element == 'Cron Scripts':
            stdin, stdout, stderr = client.exec_command('ls /etc/cron.d/')
            cron_check = stdout.read().decode()
            if valeur == "Présent" and "apt" not in cron_check:
                print(f"Installation du script cron {element}...")
                client.exec_command("sudo touch /etc/cron.d/apt-compat")
                elements_installes.append(element)
        
        # Ajoutez des conditions similaires pour d'autres éléments attendus...

    return elements_installes


def handle_problematic_elements(client, elements_problématiques):
    """Traiter les éléments problématiques en les supprimant ou en appliquant des correctifs."""
    for element, details in elements_problématiques.items():
        print(f"{element}: Attendu: {details['Attendu']} - Détecté: {details['Détecté']}")
        
        user_choice = input(f"Voulez-vous supprimer {element} ? (o/n): ").strip().lower()
        if user_choice == 'o':
            print(f"Suppression de {element}...")
            # Exemple de suppression d'élément problématique (ajustez selon les besoins)
            client.exec_command(f"sudo rm -f {element}")
        else:
            print(f"{element} n'a pas été supprimé.")

def apply_R61(yaml_file, client):
    """Appliquer la recommandation R61 et mettre à jour le YAML."""
    print("Application de la recommandation R61")

    # Charger le fichier YAML
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    rule_data = data.get("R61", {})
    
    # Vérifier si la règle est déjà appliquée
    if rule_data.get('appliquer', False):
        print("La règle R61 est déjà appliquée.")
        return

    # Récupérer les éléments attendus et détectés
    elements_attendus = rule_data.get('éléments_attendus', {})
    elements_detectes = rule_data.get('éléments_détectés', {})
    elements_problématiques = rule_data.get('éléments_problématiques', {})

    # Vérification et installation des éléments attendus
    elements_installes = install_expected_elements(yaml_file, client)

    # Si des éléments problématiques existent, proposer de les supprimer ou les corriger
    if elements_problématiques:
        print("Des éléments problématiques ont été détectés.")
        handle_problematic_elements(client, elements_problématiques)
    
    # Demander l'approbation avant de continuer
    if ask_for_approval("R61"):
        # Mettre à jour la clé 'appliquer' et le statut dans le YAML
        update_yaml_status(yaml_file, "R61", elements_problématiques)
    else:
        print("La règle R61 n'a pas été appliquée.")

def update_yaml_status(yaml_file, rule, elements_problématiques):
    """Mettre à jour le fichier YAML avec le statut de conformité et la clé 'appliquer'."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    rule_data = data.get(rule, {})
    
    if elements_problématiques:
        rule_data['status'] = 'Non conforme'
        rule_data['appliquer'] = False  # Appliquer reste à False si des éléments problématiques existent
    else:
        rule_data['status'] = 'Conforme'
        rule_data['appliquer'] = True  # Appliquer devient True si tout est conforme
        rule_data['éléments_détectés'] = []  # Réinitialisation des éléments détectés
    
    # Mettre à jour le YAML avec les nouvelles informations
    data[rule] = rule_data
    
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file, allow_unicode=True)  # Assurez-vous que l'encodage UTF-8 et les caractères spéciaux sont gérés

def apply_recommandation_mise_a_jour_min(yaml_file, client):
    """Appliquer les recommandations de sécurité en fonction du fichier YAML."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    for rule, rule_data in data.items():
        if not rule_data.get('appliquer', False):
            print(f"Application de la règle {rule}...")
            if rule == "R61":
                apply_R61(yaml_file, client)
            else:
                print(f"Règle inconnue : {rule}")
        else:
            print(f"Règle {rule} déjà appliquée.")
