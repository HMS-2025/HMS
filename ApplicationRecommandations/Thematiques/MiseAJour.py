import subprocess
import os
import yaml

def update_yaml(yaml_file, thematique ,  rule, clear_keys=[]):
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Conforme'
    with open(yaml_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def apply_R61(yaml_file, client):
    """Appliquer la recommandation R61 et mettre à jour le YAML."""
    print("Application de la recommandation R61")
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)    

    if not data["mise_a_jour"]["R61"]['apply']:
        return None
    else : 
        # Enable and start unattended-upgrades service
        client.exec_command("sudo apt-get install -y unattended-upgrades")
        client.exec_command("sudo systemctl enable unattended-upgrades")
        client.exec_command("sudo systemctl start unattended-upgrades")
        
        # Ensure APT::Periodic::Unattended-Upgrade is enabled
        client.exec_command("echo 'APT::Periodic::Unattended-Upgrade \"1\";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades")
        
        # Create a cron job to perform updates
        cron_job = "0 4 * * * /usr/bin/apt update && /usr/bin/apt upgrade -y"
        client.exec_command(f"(sudo crontab -l ; echo '{cron_job}') | sudo crontab -")
        
        # Ensure the apt-compat script is present in /etc/cron.daily/
        client.exec_command("sudo cp /usr/lib/apt/apt.systemd.daily /etc/cron.daily/apt-compat")
        
        # Ensure the apt-daily.timer is enabled and started
        client.exec_command("sudo systemctl enable apt-daily.timer")
        client.exec_command("sudo systemctl start apt-daily.timer")

        update_yaml(yaml_file, 'mise_a_jour' , 'R61')
        
def apply_rule(rule_name, yaml_file, client , level):
    if level == 'min' : 
        if rule_name == "R61":
            apply_R61(yaml_file, client)   
        else:
            print(f"Règle inconnue : {rule_name}")
    elif level == "moyen" : 
        pass
    else : 
        pass

def apply_recommandation_mise_a_jour(yaml_file, client , level):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)
            
        if not data or 'mise_a_jour' not in data:
            return
        for rule, rule_data in data['mise_a_jour'].items():
            if not rule_data.get('apply', False):
                print(f"Règle {rule} déjà appliquée.")
            else:
                apply_rule(rule, yaml_file, client , level)
                
    except FileNotFoundError:
        print(f"Fichier {yaml_file} non trouvé.")
    except yaml.YAMLError as e:
        print(f"Erreur lors de la lecture du fichier YAML : {e}")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite : {e}")


