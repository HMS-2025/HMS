import subprocess
import yaml
import os

def ask_for_approval(rule, detected_elements):
    """Demander à l'utilisateur s'il souhaite appliquer la règle spécifiée après avoir affiché les éléments détectés."""
    print(f"Éléments détectés pour la règle {rule}:")
    for elem in detected_elements:
        print(f"- {elem}")
    
    response = input(f"Voulez-vous appliquer la règle {rule} sur ces éléments ? (o/n): ").strip().lower()
    return response == 'o'

def disable_user_shell(user, client):
    print(f"Changement du shell(desactivation) pour l'utilisateur {user} à /usr/sbin/nologin...")
    try:
        client.exec_command(f'sudo usermod -s /usr/sbin/nologin {user}')
    except Exception as e:
        print(f"Erreur lors du changement du shell pour {user} : {e}")
        exit(1)

def delete_user_account(user, client):
    print(f"Suppression du compte utilisateur {user}...")
    try:
        client.exec_command(f'sudo userdel -r {user}')
    except Exception as e:
        print(f"Erreur lors de la suppression du compte {user} : {e}")
        exit(1)

def update_yaml(yaml_file, rule):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[rule] = {
        'appliquer': True,        
        'elements_detectes': [],
        'status': 'Conforme'
    }
    
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R30(yaml_file, client):
    print("Application de la recommandation R30")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    users_detected = data.get('R30', {}).get('elements_detectes', [])
    if not users_detected:
        print("Aucun utilisateur à désactiver dans la règle R30.")
        return
    
    if ask_for_approval("R30", users_detected):
        for user in users_detected:
            disable_user_shell(user, client)
        update_yaml(yaml_file, 'R30')
    else:
        print("Application de la règle R30 annulée.")

def apply_R53(yaml_file, client):
    print("Application de la recommandation R53")
    try:
        stdin, stdout, stderr = client.exec_command('find / -nouser -o -nogroup')
        files = stdout.read().decode().strip().split('\n')
        files = [file for file in files if file]  # Filtrer les lignes vides
        
        if not files:
            print("Aucun fichier ou répertoire sans utilisateur ou groupe trouvé.")
            return
        
        print("Fichiers et répertoires sans utilisateur ou groupe :")
        for file in files:
            print(file)
        
        if ask_for_approval("R53", files):
            for file in files:
                try:
                    client.exec_command(f'sudo rm -f {file}')
                    print(f"Fichier supprimé : {file}")
                except Exception as e:
                    print(f"Erreur lors de la suppression de {file} : {e}")
            update_yaml(yaml_file, 'R53')
        else:
            print("Aucune suppression effectuée.")
    except Exception as e:
        print(f"Erreur lors de la recherche des fichiers : {e}")

def apply_R56(yaml_file, client):
    print("Application de la recommandation R56")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    elements_detectes = data.get('R56', {}).get('elements_detectes', [])
    if not elements_detectes:
        print("Aucun fichier détecté avec setuid ou setgid à modifier.")
        return
    
    if ask_for_approval("R56", elements_detectes):
        print("Désactivation des permissions setuid et setgid sur les fichiers suivants :")
        for file in elements_detectes:
            stdin, stdout, stderr = client.exec_command(f'test -f {file} && sudo chmod u-s,g-s {file}')
            if stdout.channel.recv_exit_status() == 0:
                print(f"Modification des permissions sur : {file}")
            else:
                print(f"Fichier non trouvé : {file}")
        update_yaml(yaml_file, 'R56')
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
        if not rule_data.get('appliquer', False):
            print(f"Application de la règle {rule}...")
            apply_rule(rule, yaml_file, client)
        else:
            print(f"Règle {rule} déjà appliquée.")



#apply_recommandation_acces_min(yaml_file_acces_min, client)