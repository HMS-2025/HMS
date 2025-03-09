import yaml

def ask_for_approval(rule, detected_elements):
    """Demander à l'utilisateur s'il souhaite appliquer la règle spécifiée après avoir affiché les éléments détectés."""
    print(f"Éléments détectés non attendus pour la règle {rule}:")
    for elem in detected_elements:
        print(f"- {elem}")
    
    response = input(f"Voulez-vous appliquer la règle {rule} et traiter ces éléments ? (o/n): ").strip().lower()
    return response == 'o'

def ask_for_element_approval(rule, elem):
    """Demande à l'utilisateur s'il souhaite appliquer la règle pour un élément spécifique."""
    while True:
        response = input(f"Voulez-vous supprimer {elem} en application de {rule} ? (o/n/q pour quitter la règle): ").strip().lower()
        
        if response in ['o', 'n', 'q']:
            return response
        else:
            print("Réponse invalide. Entrez 'o' pour oui, 'n' pour non ou 'q' pour quitter.")

def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R58(yaml_file, client):
    print("Application de la recommandation R58")
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    expected_packages = data.get("R58", {}).get("éléments_attendus", [])
    
    if not expected_packages:
        print("Aucun paquet attendu défini dans la règle R58.")
        return
    
    stdin, stdout, stderr = client.exec_command("dpkg -l | awk '{print $2}'")
    error = stderr.read().decode().strip()
    if error:
        print(f"Erreur lors de la récupération des paquets installés : {error}")
        return
    
    installed_packages = stdout.read().decode().splitlines()
    
    detected_elements = [pkg for pkg in installed_packages if pkg and pkg not in expected_packages]
    
    if detected_elements and ask_for_approval("R58", detected_elements):
        for elem in detected_elements:
            response = ask_for_element_approval("R58", elem)
            if response == 'q':
                print("Quitter l'application de la règle R58.")
                break
            elif response == 'o':
                print(f"Suppression du paquet {elem} en cours...")
                stdin, stdout, stderr = client.exec_command(f'sudo apt-get remove --purge -y {elem}')
                error = stderr.read().decode().strip()
                if error:
                    print(f"Erreur lors de la suppression du paquet {elem} : {error}")
                else:
                    print(f"Le paquet {elem} a été supprimé avec succès.")
            else:
                print(f"Le paquet {elem} n'a pas été supprimé.")
    
        update_yaml(yaml_file, "R58", detected_elements)

def apply_R59(yaml_file, client):
    print("Application de la recommandation R59")
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    problematic_repos = data.get("R59", {}).get("detected_elements", [])
    
    if not problematic_repos:
        print("Aucun dépôt problématique défini dans la règle R59.")
        return
    
    detected_elements = problematic_repos  
    
    if detected_elements and ask_for_approval("R59", detected_elements):
        sources_file = "/etc/apt/sources.list"
        
        for repo in detected_elements:
            response = ask_for_element_approval("R59", repo)
            if response == 'q':
                print("Quitter l'application de la règle R59.")
                break
            elif response == 'o':
                print(f"Suppression du dépôt {repo} en cours...")
                stdin, stdout, stderr = client.exec_command(f'sudo sed -i "/{repo}/d" {sources_file}')
                error = stderr.read().decode().strip()
                if error:
                    print(f"Erreur lors de la suppression du dépôt {repo} : {error}")
                else:
                    print(f"Dépôt {repo} supprimé avec succès.")
            else:
                print(f"Le dépôt {repo} n'a pas été supprimé.")
    
        update_yaml(yaml_file, "R59", detected_elements)

def apply_rule(rule_name, yaml_file, client , level):
    if level : 
        if rule_name == "R58":
            apply_R58(yaml_file, client)
        elif rule_name == "R59":
            apply_R59(yaml_file, client)
        else:
            print(f"Règle inconnue : {rule_name}")
    elif level == "moyen" : 
        pass
    else : 
        pass

def apply_recommandation_maintenance(yaml_file, client , level):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)  
        if not data or 'maintenance' not in data:
            return
        for rule, rule_data in data['maintenance'].items():
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