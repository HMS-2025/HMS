import yaml
import os
import paramiko

# Charger les références depuis Reference_min.yaml ou Reference_Moyen.yaml
def load_reference_yaml(niveau):
    """Charge le fichier de référence correspondant au niveau choisi (min ou moyen)."""
    file_path = f"AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}

# Exécution d'une commande SSH
def execute_ssh_command(serveur, command):
    stdin, stdout, stderr = serveur.exec_command(command)
    output = stdout.read().decode().strip().split("\n")
    return list(filter(None, output))

# Vérification de conformité des règles
def check_compliance(rule_id, detected_values, reference_data):
    """Vérifie la conformité des règles en comparant les valeurs détectées avec les références."""
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    
    if isinstance(expected_values, dict):
        expected_values_list = list(expected_values.values())
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    else:
        expected_values_list = [expected_values]
    
    detected_values_list = detected_values if isinstance(detected_values, list) else list(detected_values.values())
    
    
    return {
        "apply": detected_values_list == expected_values_list,
        "status": "Conforme" if detected_values_list == expected_values_list else "Non-conforme",
        "expected_elements": expected_values_list if expected_values_list else "None",
        "detected_elements": detected_values_list if detected_values_list else "None"
    }

# Fonction principale d'analyse du système
def analyse_systeme(serveur, niveau, reference_data=None):
    """Analyse le système et génère un rapport YAML avec les résultats de conformité."""
    if reference_data is None:
        reference_data = load_reference_yaml(niveau)
    
    report = {}
    rules = {
        "min": {},
        "moyen": {
            "R8": (check_memory_configuration, "Vérifier la configuration mémoire"),
            "R9": (check_kernel_configuration, "Vérifier la configuration du noyau"),
            "R11": (check_yama_lsm, "Vérifier l'activation de Yama LSM"),
            "R14": (check_filesystem_configuration, "Vérifier la configuration du système de fichiers"),
        }
    }
    
    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            print(f"-> Vérification de la règle {rule_id} # {comment}")
            expected_values = reference_data.get(rule_id, {}).get("expected", {})
            detected_values = function(serveur, expected_values)
            report[rule_id] = check_compliance(rule_id, detected_values, reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml")
    compliance_percentage = sum(1 for r in report.values() if r["status"] == "Conforme") / len(report) * 100 if report else 100
    print(f"\nTaux de conformité pour le niveau {niveau.upper()} (Système) : {compliance_percentage:.2f}%")


# --- R8: Memory Configuration Settings ---
def check_memory_configuration(serveur, expected_params):
    """Checks memory configuration parameters in GRUB settings."""

    # Lire la configuration GRUB pour récupérer GRUB_CMDLINE_LINUX_DEFAULT
    command = "grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT=\"//;s/\"$//'"
    stdin, stdout, stderr = serveur.exec_command(command)
    
    # Extraction des options en supprimant les doublons
    grub_cmdline = list(set(stdout.read().decode().strip().split()))

    # Vérifier les éléments détectés
    detected_elements = [param for param in grub_cmdline if param in expected_params]

    # S'assurer que detected_elements est vide si aucun élément n'est trouvé
    return detected_elements if detected_elements else []

# --- R9: Kernel Configuration ---
def check_kernel_configuration(serveur, expected_settings):
    """Checks kernel configuration settings in sysctl based on reference_moyen.yaml."""
    
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()

    return detected_settings

# --- R11: Yama LSM Activation ---
def check_yama_lsm(serveur, expected_value):
    """Checks if Yama LSM is enabled and properly configured."""
    
    command = "sysctl -n kernel.yama.ptrace_scope"
    stdin, stdout, stderr = serveur.exec_command(command)
    yama_status = stdout.read().decode().strip()

    return {"kernel.yama.ptrace_scope": yama_status}

# --- R14: Filesystem Configuration Settings ---
def check_filesystem_configuration(serveur, expected_settings):
    """Checks recommended filesystem settings in sysctl based on reference_moyen.yaml."""
    
    detected_settings = {}
    for param in expected_settings:
        command = f"sysctl -n {param}"
        stdin, stdout, stderr = serveur.exec_command(command)
        detected_settings[param] = stdout.read().decode().strip()

    return detected_settings

# Sauvegarde du rapport YAML
def save_yaml_report(data, output_file):
    """Sauvegarde les résultats de l'analyse dans un fichier YAML sans alias."""
    if not data:
        return
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "a", encoding="utf-8") as file:
        yaml.safe_dump({"system": data}, file, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"Rapport généré : {output_path}")
