import subprocess
import os
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
    
    problematic_repos = data.get("R59", {}).get("éléments_problématiques", [])
    
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

def update_yaml(yaml_file, rule, detected_elements):
    """Met à jour le fichier YAML en fonction des éléments détectés."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    rule_data = data.get(rule, {})
    rule_data['elements_detectes'] = detected_elements
    rule_data['status'] = 'Conforme' if not detected_elements else 'Non conforme'
    rule_data['appliquer'] = True
    
    data[rule] = rule_data
    
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file, default_flow_style=False, allow_unicode=True)

def apply_rule(rule_name, yaml_file, client):
    if rule_name == "R58":
        apply_R58(yaml_file, client)
    elif rule_name == "R59":
        apply_R59(yaml_file, client)
    else:
        print(f"Règle inconnue : {rule_name}")

def apply_recommandation_maintenance_min(yaml_file, client):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    for rule, rule_data in data.items():
        if not rule_data.get('appliquer', False):
            print(f"Application de la règle {rule}...")
            apply_rule(rule, yaml_file, client)
        else:
            print(f"Règle {rule} déjà appliquée.")


# Appeler la fonction de maintenance avec le chemin du fichier YAML et le client SSH
# apply_recommandation_maintenance_min("/path/to/maintenance_minimal.yml", client)
