import yaml
import os
import paramiko

# Exécuter une commande SSH sur le serveur distant et retourner le résultat
def execute_ssh_command(server, command):
    stdin, stdout, stderr = server.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Vérifier la conformité des règles en comparant les valeurs détectées avec les valeurs attendues
def check_compliance(rule_id, detected_values, reference_data):
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    
    if not isinstance(expected_values, dict):
        expected_values = {}

    formatted_detected = {
        key: " | ".join(value) if isinstance(value, list) else value
        for key, value in detected_values.items()
    }
    
    formatted_expected = {
        key: " | ".join(value) if isinstance(value, list) else value
        for key, value in expected_values.items()
    }

    # Vérification des mises à jour automatiques
    if rule_id == "R61":
        cron_updates = "Cron Updates" in detected_values and detected_values["Cron Updates"] != "No cron job detected"
        cron_scripts = "Cron Scripts" in detected_values and detected_values["Cron Scripts"] == "apt-compat"
        unattended_upgrades = "Unattended Upgrades" in detected_values and "enabled" in detected_values["Unattended Upgrades"]
        systemd_timers = "Systemd Timer" in detected_values and "apt-daily.timer" in detected_values["Systemd Timer"]

        # Formule de conformité ANSSI
        is_compliant = ((cron_updates and cron_scripts) or (cron_scripts and unattended_upgrades and systemd_timers))

        return {
            "apply": is_compliant,
            "status": "Conforme" if is_compliant else "Non-conforme",
            "expected_elements": formatted_expected or "None",
            "detected_elements": formatted_detected or "None"
        }

# Vérifier l'état des mises à jour automatiques

def get_check_auto_updates(server):
    # Récupération des informations sur les unattended upgrades
    unattended_upgrades_status = " | ".join(execute_ssh_command(
        server, "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null"
    )) + " | " + " | ".join(execute_ssh_command(
        server, "systemctl is-enabled unattended-upgrades 2>/dev/null"
    )) + " | " + " | ".join(execute_ssh_command(
        server, "systemctl is-active unattended-upgrades 2>/dev/null"
    )) + " | " + " | ".join(execute_ssh_command(
        server, "grep -E '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -q '1' && echo 'enabled' || echo 'disabled'"
    ))

    # Vérification de la présence d'un cron job effectuant des mises à jour
    cron_updates = execute_ssh_command(
        server, "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'No cron job detected'"
    )
    if "No cron job detected" not in cron_updates:
        cron_updates = "apt update && apt upgrade -y"
    else:
        cron_updates = "No cron job detected"

    # Vérification de la présence du script apt-compat dans /etc/cron.daily/
    cron_scripts = execute_ssh_command(
        server, "ls -1 /etc/cron.daily/ 2>/dev/null | grep -E '^apt-compat$' && echo 'apt-compat' || echo 'Not present'"
    )
    cron_scripts = " | ".join(set(cron_scripts))  # Suppression des doublons

    # Vérification des timers systemd pour apt-daily et apt-daily-upgrade
    systemd_timer = execute_ssh_command(
        server, "systemctl list-timers --all | grep -E 'apt-daily|apt-daily-upgrade'"
    )
    if systemd_timer:
        systemd_timer = "apt-daily.timer"
    else:
        systemd_timer = "Not present"

    update_status = {
        "Unattended Upgrades": unattended_upgrades_status,
        "Cron Updates": cron_updates,
        "Cron Scripts": cron_scripts,
        "Systemd Timer": systemd_timer
    }

    return update_status


# Analyser les paramètres de mise à jour du système et générer un rapport de conformité
def analyse_mise_a_jour(server, niveau, reference_data):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R61": (get_check_auto_updates, "Vérifier l'état des mises à jour automatiques"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Vérification de la règle {rule_id} # {comment}")
            report[rule_id] = check_compliance(rule_id, function(server), reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Conforme") / len(report) * 100 if report else 0
    print(f"\nTaux de conformité pour le niveau {niveau.upper()} (Mises à jour) : {compliance_percentage:.2f}%")

# Sauvegarder le rapport d'analyse au format YAML

def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "a", encoding="utf-8") as file:
        file.write("mise_a_jour:\n")
        
        for rule_id, content in data.items():
            comment = rules.get(niveau, {}).get(rule_id, (None, ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n") 
        file.write("\n")
    
    print(f"Rapport généré: {output_path}")