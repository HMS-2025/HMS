import yaml
import os

#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"


def execute_ssh_command(serveur, command):
    """Exécute une commande SSH sur le serveur distant et retourne la sortie."""
    stdin, stdout, stderr = serveur.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

def update(application_file, analyse_file, thematique, rule):
    # Mise à jour dans le fichier d'application 
    with open(application_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Compliant'
    with open(application_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

    # Mise à jour dans le fichier d'analyse 
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


def apply_r31(serveur, report):
    r31_data = report.get("R31", {})
    if not r31_data.get("apply", False):
        print("- R31: No action required.")
        return "Compliant"
    
    print("- Applying password policy (R31)...")

    execute_ssh_command(serveur, "sudo apt install libpam-pwquality -y")
    rule = "password requisite pam_pwquality.so retry=3 minlen=12 difok=3"
    target_file = "/etc/pam.d/common-password"

    # Command to check for the rule ignoring lines starting with '#'
    grep_cmd = (
        f"sudo grep -v '^[[:space:]]*#' {target_file} | grep -qF '{rule}' && echo FOUND || echo NOTFOUND"
    )
    rule_present = execute_ssh_command(serveur, grep_cmd)

    # If the rule is not found, append it to the file
    if "NOTFOUND" in rule_present[0]:  # Check the first element of the returned output
        append_cmd = f"echo '{rule}' | sudo tee -a {target_file} > /dev/null"
        execute_ssh_command(serveur, append_cmd)
        print(f"Rule added: {rule}")
    else:
        print(f"Rule already present: {rule}")
        
    execute_ssh_command(serveur, "sudo chage -M 90 $(whoami)")
    
    execute_ssh_command(
        serveur,
        "sudo sed -i 's/^deny=.*/deny=3/' /etc/security/faillock.conf")
            
    execute_ssh_command(serveur ,"echo 'deny=3' | sudo tee -a /etc/security/faillock.conf")


    print("- R31: Password policy updated.")
    update_report('min', 'password', 'R31')

def apply_r68(serveur, report):
    r68_data = report.get("R68", {})
    if not r68_data.get("apply", False):
        print("- R68: No action required.")
        return "Compliant"

    print("- Applying password storage protection (R68)...")

    execute_ssh_command(serveur, "sudo chmod 640 /etc/shadow")
    execute_ssh_command(serveur, "sudo chown root:shadow /etc/shadow")

    print("- R68: Shadow file permissions updated.")
    update_report('min', 'password', 'R68')

def apply_password_policy(serveur, niveau, report_data):
    """Applies password policy rules based on the specified level."""
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("password", None)
    if apply_data is None:
        return

    rules = {
        "min": {
            "R31": (apply_r31, "Enforce password policy"),
            "R68": (apply_r68, "Secure password storage (e.g., /etc/shadow)")
        },
        "moyen": {
            # Règles intermédiaires à compléter si nécessaire
        },
        "avancé": {
            # Règles avancées à compléter si nécessaire
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, None):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(serveur, apply_data)

    print(f"\n- Corrections applied - PASSWORD POLICY - Level {niveau.upper()}")
