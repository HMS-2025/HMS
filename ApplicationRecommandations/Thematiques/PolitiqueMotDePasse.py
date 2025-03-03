import paramiko
import yaml

def ask_for_approval(rule):
    response = input(f"Voulez-vous appliquer la règle {rule} ? (o/n): ").strip().lower()
    return response == 'o'

def update_yaml(yaml_file, rule, success, elements_problématiques):
    """Mettre à jour directement le fichier YAML en fonction du succès de l'application de la règle."""
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    rule_data = data.get(rule, {})

    if success:
        rule_data['status'] = 'Conforme'
        rule_data['appliquer'] = True
    else:
        rule_data['status'] = 'Non conforme'
        rule_data['appliquer'] = False

    rule_data['éléments_problématiques'] = elements_problématiques
    data[rule] = rule_data

    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)

    print(f"Le statut de la règle {rule} a été mis à jour dans {yaml_file}.")

def execute_ssh_command(client, command):
    """Exécute une commande SSH sur le client distant et retourne la sortie."""
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()

    if error:
        print(f"Erreur lors de l'exécution de '{command}': {error.strip()}")
    
    return output.strip()

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

    # Appliquer la règle R31 via SSH
    execute_ssh_command(client, "sudo sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password")
    execute_ssh_command(client, "echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' | sudo tee -a /etc/pam.d/common-password")
    execute_ssh_command(client, "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
    execute_ssh_command(client, "sudo sed -i 's/^deny=.*/deny=3/' /etc/security/faillock.conf")

    print("Politique de mot de passe robuste appliquée.")
    success = True

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

    # Appliquer la règle R68 via SSH
    execute_ssh_command(client, "sudo chmod 640 /etc/shadow")
    execute_ssh_command(client, "sudo chown root:shadow /etc/shadow")

    print("Permissions de /etc/shadow corrigées.")
    success = True

    update_yaml(yaml_file, "R68", success, elements_problématiques)

def apply_recommandation_politique_mot_de_passe_min(yaml_file,client):
    """Connexion SSH et application des recommandations."""
    apply_R31(yaml_file, client)
    apply_R68(yaml_file, client)


"""

print("R31 : Attention, l'application de cette règle risque de bloquer l'accès des utilisateurs dont les mots de passe ne respectent pas les nouvelles contraintes (longueur, complexité) et d’interrompre des services automatisés utilisant des identifiants non conformes. Pour cela, il faut tester les modifications sur votre serveur de test (copie du prod), informer les utilisateurs des nouvelles exigences afin qu’ils mettent à jour leurs mots de passe en amont, vérifier l'impact sur les services critiques et prévoir un accès de secours en cas de verrouillage involontaire. Pour appliquer cette regle voici les commande à executer:")

print("\n 1) sudo sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password\n 2) echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' | sudo tee -a /etc/pam.d/common-password\n 3) sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs\n 4) sudo sed -i 's/^deny=.*/deny=3/' /etc/security/faillock.conf\n ")

print("R68 : Attention, l'application de cette règle risque d'empêcher certains services d’accéder au fichier /etc/shadow, ce qui peut bloquer l’authentification de certains processus dépendants. Pour cela, il faudra identifier vos services nécessitant un accès à ce fichier, vérifier leur compatibilité après modification, tester la configuration sur votre serveur de test (copie du prod) et s’assurer qun’un accès root est disponible pour rétablir rapidement les permissions si nécessaire. Voici les commandes à executer pour appliquer cette regle: ")

print("\n 1) sudo chmod 640 /etc/shadow \n 2) sudo chown root:shadow /etc/shadow")



"""
