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

# ============================
# RULES - MINIMAL
# ============================

def apply_r62(serveur, report):
    r62_data = report.get("R62", {})
    if not r62_data.get("apply", False):
        print("R62: No action required.")
        return "Compliant"

    prohibited_services = r62_data.get("detected_prohibited_elements", [])
    if not prohibited_services:
        print(" No prohibited services detected.")
        return "Compliant"

    print(" Applying rule R62: Disabling prohibited services...")

    for service in prohibited_services:
        print(f" Disabling {service} and its associated sockets")
        execute_ssh_command(serveur, f"sudo systemctl stop {service}")
        execute_ssh_command(serveur, f"sudo systemctl disable {service}")

        socket_name = service.replace(".service", ".socket")
        execute_ssh_command(serveur, f"sudo systemctl stop {socket_name}")
        execute_ssh_command(serveur, f"sudo systemctl disable {socket_name}")

    update_report('min', 'services', 'R62')

    print(" R62: Prohibited services disabled.")
    return "Applied"

# ============================
# RULES - MEDIUM
# ============================

def apply_r35(serveur, report):
    r35_data = report.get("R35", {})
    if not r35_data.get("apply", False):
        print("R35: No action required.")
        return "Compliant"

    detected_accounts = r35_data.get("detected_elements", [])
    if not detected_accounts:
        print(" No shared service accounts detected.")
        return "Compliant"

    print(" Applying rule R35: Enforcing exclusive service accounts...")
    print("The following accounts are used by multiple services:")
    for account in detected_accounts:
        user = account.split()[1]
        print(f"- {user}")

    print("\n⚠️ This rule's application is not yet supported.\n")

def apply_r63(serveur, report):
    r63_data = report.get("R63", {})
    if not r63_data.get("apply", False):
        print("R63: No action required.")
        return "Compliant"

    detected_features = r63_data.get("detected_elements", [])
    if not detected_features:
        print(" No unnecessary capabilities found.")
        return "Compliant"

    print(" Applying rule R63: Removing unnecessary capabilities...")
    print("Files with capabilities:")
    for line in detected_features:
        print(f"- {line}")

    print("\n⚠️ This rule's application is not yet supported.\n")
    return "Applied"

def apply_r74(serveur, report):
    r74_data = report.get("R74", {})
    if not r74_data.get("apply", False):
        print("R74: No action required.")
        return "Compliant"

    print(" Applying rule R74: Hardening the local mail service...")

    expected = r74_data.get("expected_elements", {}).get("hardened_mail_service", {})

    for interface in expected.get("listen_interfaces", []):
        execute_ssh_command(serveur, f"sudo postconf -e 'inet_interfaces = {interface}'")

    # Ask user for domains to add to mydestination
    user_input = input("Enter domains to allow for local delivery (comma separated): ")
    domaines = [d.strip() for d in user_input.split(",") if d.strip()]

    if domaines:
        domain_list = ", ".join(domaines)
        execute_ssh_command(serveur, f"sudo postconf -e 'mydestination = {domain_list}'")
        print(f"Domains added to mydestination: {domain_list}")
    else:
        print("No domains added to mydestination.")

    execute_ssh_command(serveur, "sudo systemctl restart postfix")
    update_report('moyen', 'services', 'R74')

    print(" R74: Local mail service hardened.")
    return "Applied"

def apply_r75(serveur, report):
    r75_data = report.get("R75", {})
    if not r75_data.get("apply", False):
        print("R75: No action required.")
        return "Compliant"

    print(" Applying rule R75: Configuring mail aliases for service accounts...")

    expected_aliases = r75_data.get("expected_elements", [])

    print("Found aliases:")
    for alias in expected_aliases:
        print(f"- {alias}")

    print("\n⚠️ This rule's application is not yet supported.\n")

# ============================
# MAIN
# ============================

def apply_services(client, level, report_data):
    fix_results = {}
    apply_data = report_data.get("services", None)
    if apply_data is None:
        return

    rules = {
        "min": {
            "R62": (apply_r62, "Disable prohibited services detected")
        },
        "moyen": {
            "R35": (apply_r35, "Use unique and exclusive service accounts"),
            "R63": (apply_r63, "Disable non-essential capabilities"),
            "R74": (apply_r74, "Harden the local mail service"),
            "R75": (apply_r75, "Configure mail aliases for service accounts")
        }
    }

    apply_data = report_data.get("services", {})
    if level in rules:
        for rule_id, (function, comment) in rules[level].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

    print(f"\n Fixes applied - SERVICES - Level {level.upper()}")
    return fix_results
