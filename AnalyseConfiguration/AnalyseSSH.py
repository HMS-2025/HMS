import paramiko
import yaml
import os

#-------------FONCTIONS OUTILS-----------------#

# Charge les critères de l'ANSSI 
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

# Exécute la commande sur le serveur 
def execute_commands(serveur, commands):
    if not isinstance(serveur, paramiko.SSHClient):
        print("Erreur : La connexion SSH est invalide.")
        return

    try:
        for command in commands:
            stdin, stdout, stderr = serveur.exec_command(command)
            stdout.read().decode()
            stderr.read().decode()
    except paramiko.SSHException as e:
        print(f"Erreur SSH lors de l'exécution des commandes : {e}")

# Génère le rapport ssh_conformite.yaml
def generate_yaml_report(all_rules, filename="ssh_compliance_report.yaml"):
    try:
        output_dir = "GenerationRapport/RapportAnalyse"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)

        with open(output_path, "w") as file:
            file.write("--- Rapport de l'analyse: ---\n")
            file.write("--- Changer la valeur de 'appliquer' à 'true' si vous voulez appliquer cette recommandation. \n\n\n")
            file.write("ssh_conformite:\n")

            for rule, details in all_rules.items():
                status = details.get("status", "Inconnu")
                appliquer = details.get("appliquer", False)

                # Vérification de la validité de `appliquer`
                if not isinstance(appliquer, bool):
                    appliquer = False  # Valeur par défaut en cas d'erreur

                file.write(f"  {rule}:\n")
                file.write(f"    status: \"{status}\"\n")
                if appliquer:
                    file.write(f"    appliquer: true  # Inutile de modifier, déjà appliqué\n")
                else:
                    file.write(f"    appliquer: false\n")

    except (OSError, IOError) as e:
        print(f"Erreur lors de la génération du fichier YAML : {e}")

# Compare les données de l'ANSSI et celles récupérées afin d'évaluer la conformité
def check_compliance(config):
    anssi_criteria = load_anssi_criteria()
    all_rules = {}

    if not anssi_criteria:
        print("Aucun critère de conformité chargé. Vérifiez votre fichier YAML.")
        return {}

    for rule, criteria in anssi_criteria.items():
        directive = criteria.get("directive", "Inconnu")
        expected_value = criteria.get("expected_value", "Inconnu")
        actual_value = config.get(directive, "non défini")

        if actual_value == expected_value:
            all_rules[rule] = {
                "status": "Conforme",
                "appliquer": True
            }
        else:
            all_rules[rule] = {
                "status": f"Non conforme -> '{directive}: {actual_value}' | attendu: '{directive}: {expected_value}'",
                "appliquer": False
            }

    return all_rules

# Récupère la configuration SSH
def dump_ssh_config(serveur):
    if not isinstance(serveur, paramiko.SSHClient):
        print("Erreur : serveur SSH invalide.")
        return

    try:
        stdin, stdout, stderr = serveur.exec_command("cat /etc/ssh/sshd_config")
        config_data = stdout.read().decode()

        if not config_data:
            raise ValueError("Fichier de configuration SSH vide ou inaccessible.")

        parsed_config = {}
        for line in config_data.split("\n"):
            if line.strip() and not line.strip().startswith("#"):
                key_value = line.split(None, 1)
                if len(key_value) == 2:
                    parsed_config[key_value[0]] = key_value[1]

        compliance_results = check_compliance(parsed_config)

        if compliance_results:
            generate_yaml_report(compliance_results)
        else:
            print("⚠Aucune donnée de conformité n'a été générée.")

    except (paramiko.SSHException, ValueError, AttributeError) as e:
        print(f"Erreur lors de la récupération de la configuration SSH : {e}")
