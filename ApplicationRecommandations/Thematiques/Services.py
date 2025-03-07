import yaml
import subprocess

def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R62(yaml_file, client):
    """Appliquer la recommandation R62 (Désactivation des services interdits) et mettre à jour le YAML."""
    print("Application de la recommandation R62")
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not data["services"]["R62"]["apply"]:
        print("La règle R62 n'est pas marquée pour application.")
        return None
    else:
        # Récupérer la liste des services interdits détectés
        prohibited_services = data["services"]["R62"]["detected_prohibited_elements"]

        # Afficher une confirmation pour l'utilisateur
        if prohibited_services:
            print("Les services suivants ont été détectés comme interdits et seront désactivés :")
            for service in prohibited_services:
                print(f"- {service}")
            
            confirmation = input("Confirmez-vous la désactivation de ces services ? (oui/non) : ").strip().lower()
            if confirmation != "oui":
                print("Annulation de l'application de la recommandation R62.")
                return None

        # Désactiver les services interdits détectés et leurs sockets
        for service in prohibited_services:
            print(f"Désactivation du service et de ses sockets associés : {service}")
            client.exec_command(f"sudo systemctl stop {service}")
            client.exec_command(f"sudo systemctl disable {service}")
            
            # Désactiver les sockets associés si le service peut être réactivé
            socket_name = service.replace(".service", ".socket")
            client.exec_command(f"sudo systemctl stop {socket_name}")
            client.exec_command(f"sudo systemctl disable {socket_name}")

        print("Tous les services interdits détectés et leurs sockets associés ont été désactivés.")

        # Mettre à jour le fichier YAML pour indiquer la conformité
        update_yaml(yaml_file, "services", "R62")


def apply_rule(rule_name, yaml_file, client):
    if rule_name == "R62":
        apply_R62(yaml_file, client)
    else:
        print(f"Règle inconnue : {rule_name}")

def apply_recommandation_service(yaml_file, client):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)
            
        if not data or 'services' not in data:
            return
        for rule, rule_data in data['services'].items():
            if rule_data.get('appliquer', False):
                print(f"Règle {rule} déjà appliquée.")
            else:
                apply_rule(rule, yaml_file, client)
                
    except FileNotFoundError:
        print(f"Fichier {yaml_file} non trouvé.")
    except yaml.YAMLError as e:
        print(f"Erreur lors de la lecture du fichier YAML : {e}")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite : {e}")

    