import yaml
import paramiko

def ask_for_approval(rule):
    """Demander à l'utilisateur s'il souhaite appliquer la règle spécifiée."""
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def update_yaml(yaml_file, rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[rule]['appliquer'] = True
    data[rule]['status'] = 'Conforme'
    for key in clear_keys:
        data[rule][key] = []
    
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def disable_user_shell(user, client):
    print(f"Changement du shell (désactivation) pour l'utilisateur {user} à /usr/sbin/nologin...")
    client.exec_command(f'sudo usermod -s /usr/sbin/nologin {user}')

def delete_user_account(user, client):
    print(f"Suppression du compte utilisateur {user}...")
    client.exec_command(f'sudo userdel -r {user}')

def apply_R30(yaml_file, client):
    print("Application de la recommandation R30")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    users_detected = data.get('R30', {}).get('comptes_inactifs_detectes', [])
    if not users_detected:
        print("Aucun utilisateur à désactiver dans la règle R30.")
        return
    
    if data['R30'].get('appliquer', False):
        print("R30 est déjà appliquée.")
        return
    
    print(f"Utilisateurs détectés: {', '.join(users_detected)}")
    if ask_for_approval("R30"):
        for user in users_detected:
            disable_user_shell(user, client)
        update_yaml(yaml_file, 'R30', ['comptes_inactifs_detectes'])
    else:
        print("Application de la règle R30 annulée.")

def apply_R53(yaml_file, client):
    print("Application de la recommandation R53")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    files_detected = data.get('R53', {}).get('fichiers_orphelins_detectes', [])
    if not files_detected:
        print("Aucun fichier orphelin détecté dans la règle R53.")
        return
    
    if data['R53'].get('appliquer', False):
        print("R53 est déjà appliquée.")
        return
    
    print(f"Fichiers orphelins détectés: {', '.join(files_detected)}")
    if ask_for_approval("R53"):
        for file in files_detected:
            client.exec_command(f'sudo rm -f {file}')
        update_yaml(yaml_file, 'R53', ['fichiers_orphelins_detectes'])
    else:
        print("Aucune suppression effectuée.")

def apply_R56(yaml_file, client):
    print("Application de la recommandation R56")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    elements_detectes = data.get('R56', {}).get('fichiers_suid_sgid_detectes', [])
    if not elements_detectes:
        print("Aucun fichier détecté avec setuid ou setgid à modifier.")
        return
    
    if data['R56'].get('appliquer', False):
        print("R56 est déjà appliquée.")
        return
    
    print(f"Fichiers SUID/SGID détectés: {', '.join(elements_detectes)}")
    if ask_for_approval("R56"):
        for file in elements_detectes:
            client.exec_command(f'test -f {file} && sudo chmod u-s,g-s {file}')
        update_yaml(yaml_file, 'R56', ['fichiers_suid_sgid_detectes'])
    else:
        print("Modification des permissions annulée pour R56.")

def apply_rule(rule_name, yaml_file, client):
    if rule_name == "R30":
        apply_R30(yaml_file, client)
    elif rule_name == "R53":
        apply_R53(yaml_file, client)
    elif rule_name == "R56":
        apply_R56(yaml_file, client)
    else:
        print(f"Règle inconnue : {rule_name}")

def apply_recommandation_acces_min(yaml_file, client):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    for rule, rule_data in data.items():
        if rule_data.get('appliquer', False):
            print(f"Règle {rule} déjà appliquée.")
        else:
            apply_rule(rule, yaml_file, client)
