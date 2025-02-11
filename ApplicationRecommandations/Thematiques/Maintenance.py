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

def apply_R58(yaml_file, client):
    print("Application de la recommandation R58")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    expected_packages = data.get("R58", {}).get("elements_attendus", [])
    
    if not expected_packages:
        print("Aucun paquet attendu défini dans la règle R58.")
        return
    
    stdin, stdout, stderr = client.exec_command("dpkg -l | awk '{print $2}'")
    error = stderr.read().decode().strip()
    if error:
        print(f"Erreur lors de la récupération des paquets installés : {error}")
        return
    
    installed_packages = stdout.read().decode().splitlines()
    
    detected_elements = []
    for pkg in installed_packages:
        if pkg and pkg not in expected_packages:
            detected_elements.append(pkg)
    
    if detected_elements:
        if ask_for_approval("R58", detected_elements):
            for pkg in detected_elements:
                print(f"Suppression du paquet {pkg} en cours...")
                stdin, stdout, stderr = client.exec_command(f'sudo apt-get remove --purge -y {pkg}')
                error = stderr.read().decode().strip()
                if error:
                    print(f"Erreur lors de la suppression du paquet {pkg} : {error}")
                else:
                    print(f"Le paquet {pkg} a été supprimé avec succès.")
        else:
            print("Application de la règle R58 annulée.")
    
    update_yaml(yaml_file, "R58", detected_elements)

def apply_R59(yaml_file, client):
    print("Application de la recommandation R59")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    expected_repos = data.get("R59", {}).get("elements_attendus", [])
    
    if not expected_repos:
        print("Aucun dépôt attendu défini dans la règle R59.")
        return
    
    sources_files = ["/etc/apt/sources.list"]
    sources_files.extend([f"/etc/apt/sources.list.d/{f}" for f in os.listdir("/etc/apt/sources.list.d") if f.endswith('.list')])
    
    detected_elements = []
    
    for file in sources_files:
        stdin, stdout, stderr = client.exec_command(f'cat {file}')
        error = stderr.read().decode().strip()
        if error:
            print(f"Erreur lors de la lecture du fichier {file} : {error}")
            continue
        
        lines = stdout.read().decode().splitlines()
        detected_repos = [line for line in lines if line not in expected_repos]
        
        if detected_repos:
            detected_elements.extend(detected_repos)
    
    if detected_elements:
        if ask_for_approval("R59", detected_elements):
            for repo in detected_elements:
                print(f"Suppression du dépôt {repo} en cours...")
                with client.open_sftp().file(file, 'w') as f:
                    new_lines = [line for line in lines if line not in detected_repos]
                    f.write('\n'.join(new_lines) + '\n')
                    print(f"Dépôt {repo} supprimé avec succès.")
        else:
            print("Application de la règle R59 annulée.")
    
    update_yaml(yaml_file, "R59", detected_elements)

def prompt_delete_elements(detected_elements):
    """Propose à l'utilisateur de supprimer les éléments détectés non attendus."""
    print("Voulez-vous supprimer les éléments suivants ?")
    for elem in detected_elements:
        print(f"- {elem}")
    
    response = input("Entrez 'o' pour supprimer, 'n' pour annuler : ").strip().lower()
    return response == 'o'

def update_yaml(yaml_file, rule, detected_elements):
    """Met à jour le fichier YAML en fonction des éléments détectés."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    rule_data = data.get(rule, {})
    rule_data['elements_detectes'] = detected_elements
    rule_data['status'] = 'Conforme' if not detected_elements else 'Non conforme'
    rule_data['appliquer'] = True
    
    # Mettre à jour le YAML avec les nouvelles informations
    data[rule] = rule_data
    
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

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


#apply_recommandation_maintenance_min(yaml_file_maintenance_min, client)