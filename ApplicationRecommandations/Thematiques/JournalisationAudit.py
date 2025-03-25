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

def apply_r33(client, report):
    r33_data = report.get("R33", {})
    if not r33_data.get("apply", False):
        print("- R33: No action required.")
        return "Compliant"

    print("- Applying administrative action accountability setup")

    cmds = [
        "sudo apt-get install -y auditd audispd-plugins",
        "sudo systemctl enable auditd",
        "sudo systemctl start auditd",
        "sudo auditctl -e 1",
        "echo '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k admin_cmd' | sudo tee -a /etc/audit/rules.d/admin.rules",
        "echo '-w /etc/sudoers -p wa -k scope' | sudo tee -a /etc/audit/rules.d/admin.rules",
        "echo '-w /etc/sudoers.d/ -p wa -k scope' | sudo tee -a /etc/audit/rules.d/admin.rules",
        "echo '-w /var/log/sudo.log -p wa -k actions' | sudo tee -a /etc/audit/rules.d/admin.rules",
        "sudo augenrules --load",
        "sudo service auditd restart",
        "sudo sed -i 's/^Defaults\s.*logfile.*$/Defaults logfile=\\/var\\/log\\/sudo.log/' /etc/sudoers",
        "echo 'Defaults logfile=\"/var/log/sudo.log\"' | sudo tee -a /etc/sudoers"
    ]

    for cmd in cmds:
        output, err = execute_ssh_command(client, cmd)
        if err:
            print(f"Error executing '{cmd}': {err}")

    update_report('moyen', 'logging', 'R33')

def apply_logging_audit(client, niveau, report_data):
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("logging", None)
    if apply_data is None:
        return

    rules = {
        "moyen": {
            "R33": (apply_r33, "Ensure accountability of administrative actions")
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

    print(f"\n- Corrections applied - logging and audit - Level {niveau.upper()}")
