import yaml


def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R30(yaml_file, client):
    print("Application de la recommandation R30")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    
    users_detected = data["gestion_acces"]["R30"]["detected_elements"]
    
    if not users_detected:
        return None
    
    if not data["gestion_acces"]["R30"]['apply']:
        return None
    else : 
        for user in users_detected:
            client.exec_command(f'sudo passwd -l {user}')
        print("R30 appliquée avec succès")

        #Mettre a jour le fichier 
        update_yaml(yaml_file, 'gestion_acces' , 'R30')


def apply_R53(yaml_file, client):
    print("Application de la recommandation R53")

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    
    fichiers_orphelins = data["gestion_acces"]["R53"]["detected_elements"]

    if not fichiers_orphelins:
        return None
    
    if not data["gestion_acces"]["R53"]['apply']:
        return None
    else : 
        for file in fichiers_orphelins:
            client.exec_command(f'sudo rm -f {file} || sudo rm -r {file}')        
        print("R53 appliquée avec succès")

        #Mettre a jour le fichier 
        update_yaml(yaml_file, 'gestion_acces' , 'R53')

def apply_R56(yaml_file, client):
    print("Application de la recommandation R56")

    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    
    uid_gid_files = data["gestion_acces"]["R56"]["detected_elements"]
    
    if not uid_gid_files:
        return None
    
    if not data["gestion_acces"]["R56"]['apply']:
        return None
    else : 
        for file in uid_gid_files:
            client.exec_command(f'sudo chmod u-s {file}')        
            client.exec_command(f'sudo chmod g-s {file}')
            client.exec_command(f'sudo chmod o-s {file}')        
        print("R56 appliquée avec succès")

        #Mettre a jour le fichier 
        update_yaml(yaml_file, 'gestion_acces' , 'R56')

    
def apply_rule(rule_name, yaml_file, client):
    if rule_name == "R30":
        apply_R30(yaml_file, client)
    elif rule_name == "R53":
        apply_R53(yaml_file, client)
    elif rule_name == "R56":
        apply_R56(yaml_file, client)
    else:
        print(f"Règle inconnue : {rule_name}")

def apply_recommandation_acces(yaml_file, client):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    for rule, rule_data in data['gestion_acces'].items():
        if rule_data.get('appliquer', False):
            print(f"Règle {rule} déjà appliquée.")
        else:
            apply_rule(rule, yaml_file, client)
