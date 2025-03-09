import paramiko
import yaml

def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R31(yaml_file, client):
    
    """Appliquer la recommandation R31 (Politique de mot de passe) et mettre à jour le YAML."""
    print("Application de la recommandation R31")
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not data["password"]["R31"]["apply"]:
        return None
    else:
        # Mise à jour de la politique PAM

        client.exec_command(
            "sudo apt install libpam-pwquality -y"
        )

        client.exec_command(
            "grep -q 'pam_pwquality.so' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' | sudo tee -a /etc/pam.d/common-password "
        )

        # Mise à jour de la politique d'expiration des mots de passe
        client.exec_command(
            "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs"
        )

        # Configuration de faillock
        client.exec_command(
            "sudo sed -i 's/^deny=.*/deny=3/' /etc/security/faillock.conf || "
            "echo 'deny=3' | sudo tee -a /etc/security/faillock.conf"
        )

        # Mettre à jour le fichier YAML pour indiquer la conformité
        update_yaml(yaml_file, "password", "R31")


def apply_R68(yaml_file, client):

    """Appliquer la recommandation R68 (Protection des mots de passe stockés) et mettre à jour le YAML."""
    print("Application de la recommandation R68")
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not data["password"]["R68"]["apply"]:
        print("La règle R68 n'est pas marquée pour application.")
        return None
    else : 
        # Appliquer les modifications pour rendre conforme R68
        client.exec_command("sudo chmod 640 /etc/shadow")
        client.exec_command("sudo chown root:shadow /etc/shadow")

        print("Permissions de /etc/shadow corrigées.")

        # Mettre à jour le fichier YAML pour indiquer la conformité
        update_yaml(yaml_file, "password", "R68")


def apply_rule(rule_name, yaml_file, client , level):
    if level == "min" : 
        if rule_name == "R31":
            apply_R31(yaml_file, client)
        elif rule_name == "R68":
            apply_R68(yaml_file, client)      
        else:
            print(f"Règle inconnue : {rule_name}")
    elif level == "moyen" : 
        pass
    else : 
        pass

def apply_recommandation_politique_mot_de_passe(yaml_file,client , level):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)
            
        if not data or 'password' not in data:
            return
        for rule, rule_data in data['password'].items():
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
