import os
import yaml

def ask_for_approval(rule):
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def update_yaml(yaml_file, rule, success, elements_problématiques):
    """Mettre à jour directement le fichier YAML en fonction du succès de l'application de la règle."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get(rule, {})
    
    # Si la règle a été appliquée avec succès, mettre à jour l'état et l'application
    if success:
        rule_data['status'] = 'Conforme'
        rule_data['appliquer'] = True
    else:
        rule_data['status'] = 'Non conforme'
        rule_data['appliquer'] = False
    
    # Mettre à jour les éléments problématiques
    rule_data['éléments_problématiques'] = elements_problématiques
    data[rule] = rule_data
    
    # Sauvegarder les modifications dans le fichier YAML
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)

    print(f"Le statut de la règle {rule} a été mis à jour dans {yaml_file}.")

def apply_R31(yaml_file, client):
    print("Application de la recommandation R31")
    success = False
    elements_problématiques = {}

    if not ask_for_approval("R31"):
        print("Règle R31 non appliquée.")
        update_yaml(yaml_file, "R31", success, elements_problématiques)
        return

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get("R31", {})
    if rule_data.get('appliquer', False):
        print("La règle R31 est déjà appliquée.")
        update_yaml(yaml_file, "R31", success, elements_problématiques)
        return

    # Vérification des éléments problématiques
    elements_attendus = rule_data.get('éléments_attendus', {})
    elements_problématiques = rule_data.get('éléments_problématiques', {})

    if elements_problématiques:
        print("Éléments problématiques détectés :")
        for key, value in elements_problématiques.items():
            print(f"  - {key} : Attendu : {value.get('Attendu')}, Détecté : {value.get('Détecté')}")
    
    # Appliquer la règle R31
    os.system("sudo sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password")
    os.system("echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' | sudo tee -a /etc/pam.d/common-password")
    os.system("sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
    os.system("sudo sed -i 's/^deny=.*/deny=3/' /etc/security/faillock.conf")
    print("Politique de mot de passe robuste appliquée.")
    
    success = True  # Marque l'application réussie

    # Mise à jour du statut après application
    update_yaml(yaml_file, "R31", success, elements_problématiques)

def apply_R68(yaml_file, client):
    print("Application de la recommandation R68")
    success = False
    elements_problématiques = {}

    if not ask_for_approval("R68"):
        print("Règle R68 non appliquée.")
        update_yaml(yaml_file, "R68", success, elements_problématiques)
        return

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get("R68", {})
    if rule_data.get('appliquer', False):
        print("La règle R68 est déjà appliquée.")
        update_yaml(yaml_file, "R68", success, elements_problématiques)
        return

    # Vérification des éléments problématiques
    elements_attendus = rule_data.get('éléments_attendus', {})
    elements_problématiques = rule_data.get('éléments_problématiques', {})

    if elements_problématiques:
        print("Éléments problématiques détectés :")
        for key, value in elements_problématiques.items():
            print(f"  - {key} : Attendu : {value.get('Attendu')}, Détecté : {value.get('Détecté')}")
    
    # Appliquer la règle R68
    os.system("sudo chmod 640 /etc/shadow")
    os.system("sudo chown root:shadow /etc/shadow")
    print("Permissions de /etc/shadow corrigées.")
    
    success = True  # Marque l'application réussie

    # Mise à jour du statut après application
    update_yaml(yaml_file, "R68", success, elements_problématiques)

def apply_recommandation_politique_mot_de_passe_min(yaml_file, client):
    apply_R31(yaml_file, client)
    apply_R68(yaml_file, client)
