import os
import yaml

def update_yaml_status(yaml_file, rule, elements_problématiques):
    """Mettre à jour le fichier YAML avec le statut de conformité et la clé 'appliquer'."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    rule_data = data.get(rule, {})

    if any(sub_key.get("Détecté") != sub_key.get("Attendu") for sub_key in elements_problématiques.values()):
        rule_data['status'] = 'Non conforme'
        rule_data['appliquer'] = False
    else:
        rule_data['status'] = 'Conforme'
        rule_data['appliquer'] = True
    
    data[rule] = rule_data
    
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

    print(f"Le statut de la règle {rule} a été mis à jour dans {yaml_file}.")

def ask_for_approval(rule):
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def apply_R31(yaml_file, client):
    print("Application de la recommandation R31")
    if not ask_for_approval("R31"):
        print("Règle R31 non appliquée.")
        return

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get("R31", {})
    if rule_data.get('appliquer', False):
        print("La règle R31 est déjà appliquée.")
        return

    elements_problématiques = rule_data.get('éléments_problématiques', {})
    if elements_problématiques:
        print("Éléments problématiques détectés :")
        for key, value in elements_problématiques.items():
            print(f"  - {key} : Attendu : {value.get('Attendu')}, Détecté : {value.get('Détecté')}")
    
    os.system("sudo sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password")
    os.system("echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' | sudo tee -a /etc/pam.d/common-password")
    os.system("sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
    os.system("sudo sed -i 's/^deny=.*/deny=3/' /etc/security/faillock.conf")
    print("Politique de mot de passe robuste appliquée.")
    
    update_yaml_status(yaml_file, "R31", elements_problématiques)

def apply_R68(yaml_file, client):
    print("Application de la recommandation R68")
    if not ask_for_approval("R68"):
        print("Règle R68 non appliquée.")
        return

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get("R68", {})
    if rule_data.get('appliquer', False):
        print("La règle R68 est déjà appliquée.")
        return

    elements_problématiques = rule_data.get('éléments_problématiques', {})
    if elements_problématiques:
        print("Éléments problématiques détectés :")
        for key, value in elements_problématiques.items():
            print(f"  - {key} : Attendu : {value.get('Attendu')}, Détecté : {value.get('Détecté')}")
    
    os.system("sudo chmod 640 /etc/shadow")
    os.system("sudo chown root:shadow /etc/shadow")
    print("Permissions de /etc/shadow corrigées.")
    
    with open('/etc/shadow', 'r') as f:
        for line in f:
            if ':' in line:
                user, passwd = line.split(':', 1)
                if passwd in ('', '*', '!'):
                    print(f"Utilisateur {user} a un mot de passe vide ou désactivé.")
                elif not any(algo in passwd for algo in ["$6$", "$argon2$", "$scrypt$", "$pbkdf2$"]):
                    print(f"Utilisateur {user} utilise un hachage non sécurisé.")
    
    update_yaml_status(yaml_file, "R68", elements_problématiques)

def apply_recommandation_politique_mot_de_passe_min(yaml_file, client):
    apply_R31(yaml_file, client)
    apply_R68(yaml_file, client)


#apply_recommandation_politique_mot_de_passe_min(yaml_file_politiqueMotDePasse, client)