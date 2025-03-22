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

######----------------------------------------PARTIE moyen--------------------------------------------------------------------------------------------------######

import os
from ApplicationRecommandations.execute_command import execute_ssh_command

# ============================
# Fonction utilitaire commune
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
# RÈGLES SERVICES
# ============================

def apply_r35(serveur, report):
    """
    Applique la règle R35 : Utiliser des comptes de service uniques et exclusifs.
    """
    r35_data = report.get("services", {}).get("R35", {})

    if not r35_data.get("apply", False):
        print("✅ R35 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R35 : Comptes de service uniques...")

    detected_accounts = r35_data.get("detected_elements", [])
    if not detected_accounts:
        print("➡️ Aucun compte à corriger trouvé.")
        return "Conforme"

    print(f"➡️ Comptes de service à analyser : {detected_accounts}")

    # Exemple : désactivation des comptes doublons ou mal configurés
    for account in detected_accounts:
        user = account.split()[1]
        print(f"🔒 Désactivation du compte {user}")
        execute_ssh_command(serveur, f"sudo usermod -L {user}")
        execute_ssh_command(serveur, f"sudo passwd -l {user}")

    print("✅ R35 : Comptes de service sécurisés.")
    return "Appliqué"

def apply_r63(serveur, report):
    """
    Applique la règle R63 : Désactiver les fonctionnalités des services non essentielles.
    """
    r63_data = report.get("services", {}).get("R63", {})

    if not r63_data.get("apply", False):
        print("✅ R63 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R63 : Suppression des capabilities non nécessaires...")

    detected_features = r63_data.get("detected_elements", [])
    if not detected_features:
        print("➡️ Aucun service avec capability détecté.")
        return "Conforme"

    success = True

    for line in detected_features:
        binary = line.split()[0]
        print(f"➡️ Suppression des capabilities pour {binary}")
        _, stdout, stderr = serveur.exec_command(f"sudo setcap -r {binary}")
        error = stderr.read().decode().strip()
        if error:
            print(f"❌ Erreur sur {binary} : {error}")
            success = False

    if success:
        print("✅ R63 : Toutes les capabilities inutiles ont été supprimées.")
        return "Appliqué"
    else:
        print("⚠️ R63 : Problèmes lors de la suppression de capabilities.")
        return "Erreur"

def apply_r74(serveur, report):
    """
    Applique la règle R74 : Durcir le service de messagerie locale.
    """
    r74_data = report.get("services", {}).get("R74", {})

    if not r74_data.get("apply", False):
        print("✅ R74 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R74 : Durcissement du service mail local...")

    expected = r74_data.get("expected_elements", {}).get("hardened_mail_service", {})
    detected = r74_data.get("detected_elements", {})

    # Exemple avec Postfix
    for interface in expected.get("listen_interfaces", []):
        execute_ssh_command(serveur, f"sudo postconf -e 'inet_interfaces = {interface}'")

    for domain in expected.get("allow_local_delivery", []):
        execute_ssh_command(serveur, f"sudo postconf -e 'mydestination = {domain}'")

    execute_ssh_command(serveur, "sudo systemctl restart postfix")
    print("✅ R74 : Messagerie locale durcie.")
    return "Appliqué"

def apply_r75(serveur, report):
    """
    Applique la règle R75 : Configurer un alias de messagerie des comptes de service.
    """
    r75_data = report.get("services", {}).get("R75", {})

    if not r75_data.get("apply", False):
        print("✅ R75 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R75 : Configuration des alias mail pour comptes de service...")

    expected_aliases = r75_data.get("expected_elements", [])

    if not expected_aliases:
        print("➡️ Aucun alias d'attendu trouvé.")
        return "Erreur"

    for alias in expected_aliases:
        execute_ssh_command(serveur, f"echo '{alias}: admin@example.com' | sudo tee -a /etc/aliases")

    execute_ssh_command(serveur, "sudo newaliases")
    print("✅ R75 : Alias de messagerie configurés.")
    return "Appliqué"

def apply_services(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    fix_results = {}

    rules = {
        "services": {
            "moyen": {
                "R35": (apply_r35, "Utiliser des comptes de service uniques et exclusifs"),
                "R63": (apply_r63, "Désactiver les fonctionnalités des services non essentielles"),
                "R74": (apply_r74, "Durcir le service de messagerie locale"),
                "R75": (apply_r75, "Configurer un alias de messagerie des comptes de service")
            },
            "renforce": {
                # Si besoin, on ajoutera des règles pour le niveau renforcé ici
            }
        }
    }

    if niveau in rules["services"]:
        for rule_id, (function, comment) in rules["services"][niveau].items():
            print(f"-> Application de la règle {rule_id} : {comment}")
            fix_results[rule_id] = function(serveur, report_data)

    output_file = f"fixes_{niveau}_services.yml"
    save_yaml_fix_report_services(fix_results, output_file, rules, niveau)

    print(f"\n✅ Correctifs appliqués - SERVICES - Niveau {niveau.upper()} : {output_file}")
    return fix_results

