import os
import yaml

#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"


def execute_ssh_command(client, command):
    """Execute an SSH command and return output and error."""
    stdin, stdout, stderr = client.exec_command(command)
    output = list(filter(None, stdout.read().decode().strip().split("\n")))
    error = stderr.read().decode().strip()
    return output, error

def update(application_file, analyse_file, thematique, rule):
    with open(application_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Compliant'
    with open(application_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

    with open(analyse_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = True
    data[thematique][rule]['status'] = 'Compliant'
    with open(analyse_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def update_report(level, thematique, rule):
    if level == 'min':
        update(application_min, analyse_min, thematique, rule)
    elif level == 'moyen':
        update(application_moyen, analyse_moyen, thematique, rule)


def apply_r32(serveur, report):
    """
    Applique la règle R32 : Expirer les sessions utilisateur locales inactives.
    """
    r32_data = report.get("R32", {})

    if not r32_data.get("apply", False):
        print(" R32 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R32 : Expiration des sessions locales...")

    fix_success = True

    attendus = r32_data.get("expected_elements", {})
    tmout_value = attendus.get("TMOUT")
    logind_conf = attendus.get("logind_conf", {})

    if not tmout_value or not logind_conf:
        print(" R32 : Données attendues manquantes dans le rapport !")
        return "Erreur : Données manquantes"

    # Sauvegardes HMS
    execute_ssh_command(serveur, "sudo cp -n /etc/profile /etc/profile.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/bash.bashrc /etc/bash.bashrc.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/systemd/logind.conf /etc/systemd/logind.conf.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/login.defs /etc/login.defs.HMS.bak")

    # CONFIGURATION DE TMOUT
    tmout_directives = [
        f"TMOUT={tmout_value}",
        "readonly TMOUT",
        "export TMOUT"
    ]

    tmout_files = ["/etc/profile", "/etc/bash.bashrc"]

    for file in tmout_files:
        print(f"➡️  Mise à jour de {file}")
        for directive in tmout_directives:
            param_name = directive.split('=')[0]
            execute_ssh_command(serveur, f"sudo sed -i '/^{param_name}/d' {file}")
            execute_ssh_command(serveur, f"echo '{directive}' | sudo tee -a {file}")

    # CONFIGURATION DU LOGIN_TIMEOUT DANS login.defs
    print("➡️  Mise à jour de /etc/login.defs")
    execute_ssh_command(serveur, "sudo sed -i '/^LOGIN_TIMEOUT/d' /etc/login.defs")
    execute_ssh_command(serveur, "echo 'LOGIN_TIMEOUT 60' | sudo tee -a /etc/login.defs")

    # CONFIGURATION DU logind.conf
    print("➡️  Mise à jour de /etc/systemd/logind.conf")
    for param, value in logind_conf.items():
        execute_ssh_command(serveur, f"sudo sed -i '/^{param}/d' /etc/systemd/logind.conf")
        execute_ssh_command(serveur, f"echo '{param}={value}' | sudo tee -a /etc/systemd/logind.conf")

    print(" Redémarrage de systemd-logind...")
    execute_ssh_command(serveur, "sudo systemctl restart systemd-logind")

    update_report('moyen', 'users', 'R32')

    print(" R32 : Expiration des sessions utilisateur locales configurée.")
    return "Appliqué" 

def apply_r69(serveur, report):
    """
    Applique la règle R69 : Sécuriser les accès aux bases utilisateurs distantes.
    """
    r69_data = report.get("R69", {})
    print(" R69: L'application de cette regle n'est pas prise en compte par notre script")

    if not r69_data.get("appliquer", False):
        print(" R69 : Aucune action nécessaire.")
        return "Conforme"
    


    return "Appliqué"

def apply_r70(serveur, report):
    """
    Applique la règle R70 : Séparer les comptes système et administrateurs de l'annuaire.
    """
    r70_data = report.get("R70", {})
    print(" R70: L'application de cette regle n'est pas prise en compte par notre script")


    if not r70_data.get("appliquer", False):
        print(" R70 : Aucune action nécessaire.")
        return "Conforme"

    
    return "Appliqué"

# ============================
# FONCTION PRINCIPALE UTILISATEURS
# ============================

def apply_user (serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("users", None)
    if apply_data is None:
        return

    rules = {
    
        "moyen": {
            "R32": (apply_r32, "Expirer les sessions utilisateur locales"),
            "R69": (apply_r69, "Sécuriser les accès aux bases utilisateurs distantes"),
            "R70": (apply_r70, "Séparer les comptes système et administrateurs de l'annuaire")
        },
        "renforce": {
        }
    
    }
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(serveur, apply_data)

    print(f"\n Correctifs appliqués - utilisateur - Niveau {niveau.upper()} :")
    
