# Ce fichier et coupé en deux partie (partie minimale et partie [moyen + renforcer])
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
    """Appliquer la recommandation R62 (Désactivation des services moyendits) et mettre à jour le YAML."""
    print("Application de la recommandation R62")
    
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not data["services"]["R62"]["apply"]:
        print("La règle R62 n'est pas marquée pour application.")
        return None
    else:
        # Récupérer la liste des services moyendits détectés
        prohibited_services = data["services"]["R62"]["detected_prohibited_elements"]

        # Afficher une confirmation pour l'utilisateur
        if prohibited_services:
            print("Les services suivants ont été détectés comme moyendits et seront désactivés :")
            for service in prohibited_services:
                print(f"- {service}")
            
            confirmation = input("Confirmez-vous la désactivation de ces services ? (oui/non) : ").strip().lower()
            if confirmation != "oui":
                print("Annulation de l'application de la recommandation R62.")
                return None

        # Désactiver les services moyendits détectés et leurs sockets
        for service in prohibited_services:
            print(f"Désactivation du service et de ses sockets associés : {service}")
            client.exec_command(f"sudo systemctl stop {service}")
            client.exec_command(f"sudo systemctl disable {service}")
            
            # Désactiver les sockets associés si le service peut être réactivé
            socket_name = service.replace(".service", ".socket")
            client.exec_command(f"sudo systemctl stop {socket_name}")
            client.exec_command(f"sudo systemctl disable {socket_name}")

        print("Tous les services moyendits détectés et leurs sockets associés ont été désactivés.")

        # Mettre à jour le fichier YAML pour indiquer la conformité
        update_yaml(yaml_file, "services", "R62")


def apply_rule(rule_name, yaml_file, client , level):
    if level == 'min' : 
        if rule_name == "R62":
            apply_R62(yaml_file, client)
        else:
            print(f"Règle inconnue : {rule_name}")
    elif level == "moyen" : 
        pass
    else : 
        pass

def apply_recommandation_service(yaml_file, client , level ):
    try:
        with open(yaml_file, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)
            
        if not data or 'services' not in data:
            return
        for rule, rule_data in data['services'].items():
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

######----------------------------------------PARTIE moyen--------------------------------------------------------------------------------------------------######

import yaml
import os

# ============================
# Fonction utilitaire commune
# ============================
def execute_ssh_command(serveur, command):
    """Exécute une commande SSH sur le serveur distant et retourne la sortie."""
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# ============================
# Fonction de sauvegarde YAML
# ============================
def save_yaml_fix_report_services(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportCorrections"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("corrections:\n")

        for rule_id, status in data.items():
            for thematique, niveaux in rules.items():
                if niveau in niveaux and rule_id in niveaux[niveau]:
                    comment = niveaux[niveau][rule_id][1]
                    file.write(f"  {rule_id}:  # {comment} ({thematique})\n")
                    file.write(f"    status: {status}\n")

    print(f"✅ Rapport des corrections SERVICES généré : {output_path}")

# ============================
# SERVICES - Correctifs
# ============================
def apply_r35(serveur, report):
    r35_data = report.get("services", {}).get("R35", {})
    if not r35_data.get("apply", False):
        print("✅ R35 : Aucune action nécessaire.")
        return "Conforme"

    print("🛠️ Vérification et correction des comptes de service...")
    service_accounts = r35_data.get("detected_elements", [])
    if not service_accounts:
        print("✅ Aucun compte de service incorrect détecté.")
        return "Conforme"

    for account in service_accounts:
        print(f"🔧 Modification du compte de service {account} pour utilisation exclusive...")
        execute_ssh_command(serveur, f"sudo usermod -s /usr/sbin/nologin {account}")

    print("✅ R35 : Tous les comptes de service ont été sécurisés.")
    return "Appliqué"

def apply_r63(serveur, report):
    r63_data = report.get("services", {}).get("R63", {})
    if not r63_data.get("apply", False):
        print("✅ R63 : Aucune action nécessaire.")
        return "Conforme"

    unnecessary_services = r63_data.get("detected_elements", [])
    if not unnecessary_services:
        print("✅ Aucun service superflu détecté.")
        return "Conforme"

    print("🛠️ Désactivation des services non essentiels...")
    for service in unnecessary_services:
        print(f"🔧 Désactivation de {service}...")
        execute_ssh_command(serveur, f"sudo systemctl disable --now {service}")

    print("✅ R63 : Tous les services inutiles ont été désactivés.")
    return "Appliqué"

def apply_r74(serveur, report):
    r74_data = report.get("services", {}).get("R74", {})
    if not r74_data.get("apply", False):
        print("✅ R74 : Aucune action nécessaire.")
        return "Conforme"

    print("🔐 Durcissement du service de messagerie locale (Postfix)...")
    execute_ssh_command(serveur, "sudo postconf -e 'inet_interfaces = loopback-only'")
    execute_ssh_command(serveur, "sudo postconf -e 'smtpd_tls_security_level = encrypt'")
    execute_ssh_command(serveur, "sudo postconf -e 'disable_vrfy_command = yes'")
    execute_ssh_command(serveur, "sudo systemctl restart postfix")

    print("✅ R74 : Service de messagerie locale durci.")
    return "Appliqué"

def apply_r75(serveur, report):
    r75_data = report.get("services", {}).get("R75", {})
    if not r75_data.get("apply", False):
        print("✅ R75 : Aucune action nécessaire.")
        return "Conforme"

    print("📧 Configuration des alias de messagerie pour les comptes de service...")
    execute_ssh_command(serveur, "sudo sed -i '/^root:/d' /etc/aliases")
    execute_ssh_command(serveur, "echo 'root: admin@example.com' | sudo tee -a /etc/aliases")
    execute_ssh_command(serveur, "sudo newaliases")

    print("✅ R75 : Alias de messagerie configuré.")
    return "Appliqué"

# ============================
# Fonction principale par niveau pour SERVICES
# ============================
def apply_services(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    fix_results = {}

    rules = {
        "moyen": {
            "R35": (apply_r35, "Utiliser des comptes de service uniques et exclusifs"),
            "R63": (apply_r63, "Désactiver les fonctionnalités des services non essentielles"),
            "R74": (apply_r74, "Durcir le service de messagerie locale"),
            "R75": (apply_r75, "Configurer un alias de messagerie des comptes de service")
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Application de la règle {rule_id} : {comment}")
            fix_results[rule_id] = function(serveur, report_data)

    save_yaml_fix_report_services(fix_results, f"fixes_{niveau}_services.yml", rules, niveau)

    yaml_path = f"GenerationRapport/RapportCorrections/fixes_{niveau}_services.yml"
    html_path = f"GenerationRapport/RapportCorrectionsHTML/fixes_{niveau}_services.html"

    print(f"\n✅ Correctifs appliqués - SERVICES - Niveau {niveau.upper()}")

