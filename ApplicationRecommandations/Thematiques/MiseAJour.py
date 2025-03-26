import yaml

#=========== Global ==========
application_min = "./GenerationRapport/RapportApplication/application_min.yml"
analyse_min = "./GenerationRapport/RapportAnalyse/analyse_min.yml"

application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"


application_renforce = "./GenerationRapport/RapportApplication/application_renforce.yml"
analyse_renforce = "./GenerationRapport/RapportAnalyse/analyse_renfore.yml"

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
    elif level == 'renforce':
        update(application_renforce, analyse_renforce, thematique, rule)

def apply_r61(client, report):
    r61_data = report.get("R61", {})
    if not r61_data.get("apply", False):
        print("- R61: No action required.")
        return "Compliant"

    print("- Applying unattended-upgrades setup")

    cmds = [
        "sudo apt-get install -y unattended-upgrades",
        "sudo systemctl enable unattended-upgrades",
        "sudo systemctl start unattended-upgrades",
        "echo 'APT::Periodic::Unattended-Upgrade \"1\";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades",
        "(sudo crontab -l ; echo '0 4 * * * /usr/bin/apt update && /usr/bin/apt upgrade -y') | sudo crontab -",
        "sudo cp /usr/lib/apt/apt.systemd.daily /etc/cron.daily/apt-compat",
        "sudo systemctl enable apt-daily.timer",
        "sudo systemctl start apt-daily.timer"
    ]

    for cmd in cmds:
        _, err = execute_ssh_command(client, cmd)
        if err:
            print(f"Error: {err}")

    update_report('min', 'updates', 'R61')

def apply_mise_a_jour(client, niveau, report_data):
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("updates", None)
    if apply_data is None:
        return

    rules = {
        "min": {
            "R61": (apply_r61, "Configurer les mises à jour automatiques avec unattended-upgrades")
        },
        "moyen": {
            # Placeholder for future medium level rules
        }
    }

    apply_data = report_data.get("updates", {})
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

    print(f"\n- Corrections applied - updates - Level {niveau.upper()}")
