import paramiko
import yaml
import os
import re

#-------------FONCTION PRINCIPALE-----------------#

# Orchestre la récupération, l'analyse et la conformité de la configuration SSH.
def check_ssh_configuration_compliance(server):
    config_data = retrieve_ssh_configuration(server)
    if config_data is None:
        return
    
    parsed_config = parse_ssh_configuration(config_data)
    compliance_results = check_anssi_compliance(parsed_config)
    
    if compliance_results:
        generate_yaml_report(compliance_results)
    else:
        print("Aucune donnée de conformité n'a été générée.")
        
def convert_time_to_seconds(time_value):
    """
    Convertit une valeur de temps SSH (ex: '2m', '30s', '1h30m') en secondes.
    """
    if time_value.isdigit():
        return int(time_value)  # Cas où c'est déjà un nombre en secondes

    time_pattern = re.findall(r'(\d+)([hms])', time_value.lower())
    
    total_seconds = 0
    for value, unit in time_pattern:
        value = int(value)
        if unit == "h":
            total_seconds += value * 3600
        elif unit == "m":
            total_seconds += value * 60
        elif unit == "s":
            total_seconds += value
    return total_seconds

#-------------FONCTIONS OUTILS-----------------#

# Charge les critères de l'ANSSI depuis un fichier YAML.
def load_anssi_criteria(file_path="AnalyseConfiguration/Thematiques/criteres_SSH.yaml"):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Le fichier {file_path} est introuvable.")

        with open(file_path, "r") as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict) or "ssh_criteria" not in data:
            raise ValueError("Format invalide du fichier YAML : section 'ssh_criteria' manquante.")

        return data.get("ssh_criteria", {})
    except (yaml.YAMLError, FileNotFoundError, ValueError) as e:
        print(f"Erreur lors du chargement des critères : {e}")
        return {}

# Exécute une liste de commandes sur le serveur via SSH.
def execute_ssh_commands(server, commands):
    if not isinstance(server, paramiko.SSHClient):
        print("Erreur : La connexion SSH est invalide.")
        return
    
    try:
        for command in commands:
            stdin, stdout, stderr = server.exec_command(command)
            stdout.read().decode()
            stderr.read().decode()
    except paramiko.SSHException as e:
        print(f"Erreur SSH lors de l'exécution des commandes : {e}")

# Génère un rapport YAML sur la conformité SSH.
def generate_yaml_report(all_rules, filename="ssh_compliance_report.yaml"):
    try:
        output_dir = "GenerationRapport/RapportAnalyse"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)

        total_rules = len(all_rules)
        compliant_rules = sum(1 for rule in all_rules.values() if rule.get("apply", False))
        compliance_percentage = (compliant_rules / total_rules) * 100 if total_rules > 0 else 0

        print(f"conformité ssh: {compliance_percentage:.1f} %")
        with open(output_path, "w") as file:
            file.write("# Rapport de l'analyse: ---\n")
            file.write("# Changer la valeur de 'apply' à 'true' si vous voulez apply cette recommandation. \n\n\n")
            file.write("ssh_conformite:\n")

            for rule, details in all_rules.items():
                status = details.get("status", "Inconnu")
                apply = details.get("apply", False)
                expected = details.get("expected_elements", [])
                detected = details.get("detected_elements", "Non défini")

                if not isinstance(apply, bool):
                    apply = False
                file.write(f"  {rule}:\n")
                file.write(f"    apply: {'true' if apply else 'false'}\n")
                file.write(f"    expected_elements: {expected}\n")
                file.write(f"    detected_elements: {detected}\n")
                file.write(f"    status: \"{status}\"\n")
    except (OSError, IOError) as e:
        print(f"Erreur lors de la génération du fichier YAML : {e}")

def check_anssi_compliance(config):
    anssi_criteria = load_anssi_criteria()
    all_rules = {}

    if not anssi_criteria:
        print("Aucun critère de conformité chargé. Vérifiez votre fichier YAML.")
        return {}

    for rule, criteria in anssi_criteria.items():
        directive = criteria.get("directive", "Inconnu")
        expected_value = criteria.get("expected_value", "Inconnu")
        actual_value = config.get(directive, "non défini")

        # Règle 1 est toujours valide
        if rule == "R1":
            status = "Conforme"
            apply = True
            expected = ["Toujours valide"]
            detected = "Automatiquement conforme car ubuntu 20.04 a SSH 2 de base."

        # Vérification spéciale pour AllowUsers et AllowGroups (doit être rempli)
        elif directive in ["AllowUsers", "AllowGroups"]:
            if actual_value == "non défini" or actual_value.strip() == "":
                status = f"Non conforme -> '{directive}' est vide ou non défini, il doit être renseigné."
                apply = False
                expected = criteria.get("expected_value", [])
                detected = "Aucun"
            else:
                status = f"Conforme -> '{directive}: {actual_value}'"
                apply = True
                expected = criteria.get("expected_value", [])
                detected = actual_value

        # Comparaison spéciale pour les valeurs de temps (ex: LoginGraceTime)
        elif directive in ["LoginGraceTime", "ClientAliveInterval"]:
            expected_seconds = convert_time_to_seconds(expected_value)
            actual_seconds = convert_time_to_seconds(actual_value)

            if actual_seconds <= expected_seconds:
                status = f"Conforme -> '{directive}: {actual_value}' | attendu: '{directive}: {expected_value}'"
                apply = True
                expected = expected_value
                detected = actual_value
            else:
                status = f"Non conforme -> '{directive}: {actual_value}' | attendu: '{directive}: {expected_value}'"
                apply = False
                expected = expected_value
                detected = actual_value

        # Comparaison classique pour les autres directives
        else:
            apply = actual_value == expected_value
            status = f"{'Conforme' if apply else 'Non conforme'} -> '{directive}: {actual_value}' | attendu: '{directive}: {expected_value}'"
            expected = expected_value
            detected = actual_value

        all_rules[rule] = {
            "status": status,
            "apply": apply,
            "expected_elements": expected if isinstance(expected, list) else [expected],
            "detected_elements": detected
        }

    return all_rules


def retrieve_ssh_configuration(server):
    if not isinstance(server, paramiko.SSHClient):
        print("Erreur : serveur SSH invalide.")
        return None
    try:
        stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config")
        config_data = stdout.read().decode()
        
        stdin, stdout, stderr = server.exec_command("cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
        extra_config_data = stdout.read().decode()
        
        if not config_data:
            raise ValueError("Fichier de configuration SSH vide ou inaccessible.")
        
        full_config = merge_ssh_configurations(config_data, extra_config_data)
        
        return full_config
    except (paramiko.SSHException, ValueError) as e:
        print(f"Erreur lors de la récupération de la configuration SSH : {e}")
        return None

def merge_ssh_configurations(base_config, extra_config):
    parsed_config = parse_ssh_configuration(base_config)
    extra_parsed_config = parse_ssh_configuration(extra_config)
    
    parsed_config.update(extra_parsed_config)
    
    merged_config = "\n".join([f"{k} {v}" for k, v in parsed_config.items()])
    return merged_config

# Analyse le fichier de configuration SSH et retourne un dictionnaire.
def parse_ssh_configuration(config_data):
    parsed_config = {}
    for line in config_data.split("\n"):
        if line.strip() and not line.strip().startswith("#"):
            key_value = line.split(None, 1)
            if len(key_value) == 2:
                parsed_config[key_value[0]] = key_value[1]
    return parsed_config
