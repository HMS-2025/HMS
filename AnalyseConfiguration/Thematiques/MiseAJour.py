import paramiko
import yaml
import os

# Charger les références depuis Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    """Charge le fichier Reference_min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data or {}
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_min.yaml : {e}")
        return {}

# Comparer les résultats de l'analyse avec les références
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si une règle est conforme en la comparant avec Reference_min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    non_compliant_items = {}
    detected_items = {}

    # Comparer chaque sous-règle
    for key, expected in expected_value.items():
        detected = rule_value.get(key, "Non détecté")

        # Correction pour Systemd Timer
        if key == "Systemd Timer" and "apt-daily.timer" in detected:
            detected = "apt-daily.timer"

        # Stocke les valeurs détectées
        detected_items[key] = detected

        # Vérifie la conformité
        if detected != expected:
            non_compliant_items[key] = {
                "Détecté": detected,
                "Attendu": expected
            }

    return {
        "status": "Non conforme" if non_compliant_items else "Conforme",
        "éléments_problématiques": non_compliant_items if non_compliant_items else "Aucun",
        "éléments_détectés": detected_items,
        "éléments_attendus": expected_value,
        "appliquer": False if non_compliant_items else True
    }

# Fonction principale pour analyser la mise à jour automatique
def analyse_mise_a_jour(serveur, niveau="min", reference_data=None):
    """Vérifie si les mises à jour automatiques sont bien configurées et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des mises à jour automatiques (R61)")
        update_status = get_check_auto_updates(serveur)
        report["R61"] = check_compliance("R61", update_status, reference_data)

    # Enregistrement du rapport
    save_yaml_report(report, "mise_a_jour_minimal.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau minimal (Mises à jour) : {compliance_percentage:.2f}%")

# R61 - Vérifier l'état des mises à jour automatiques
def get_check_auto_updates(serveur):
    """Vérifie la configuration des mises à jour automatiques sur le serveur."""
    update_status = {}

    # Vérifier si `unattended-upgrades` est installé
    command_unattended_installed = "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command_unattended_installed)
    installed_status = stdout.read().decode().strip()

    # Vérifier si `unattended-upgrades` est activé au démarrage
    command_unattended_enabled = "systemctl is-enabled unattended-upgrades 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command_unattended_enabled)
    enabled_status = stdout.read().decode().strip()

    # Vérifier si `unattended-upgrades` est actuellement actif
    command_unattended_active = "systemctl is-active unattended-upgrades 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command_unattended_active)
    active_status = stdout.read().decode().strip()

    # Vérifier la vraie activation via le fichier de configuration
    command_check_conf = "grep -E '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -q '1' && echo 'enabled' || echo 'disabled'"
    stdin, stdout, stderr = serveur.exec_command(command_check_conf)
    config_status = stdout.read().decode().strip()

    # Regrouper les statuts sous une seule clé
    update_status["Unattended Upgrades"] = f"{installed_status} | {enabled_status} | {active_status} | {config_status}"

     # Vérifier la présence de tâches cron pour les mises à jour (utilisateur root)
    command_cron = "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'Aucune tâche cron détectée'"
    stdin, stdout, stderr = serveur.exec_command(command_cron)
    output = stdout.read().decode().strip()
    update_status["Cron Updates"] = "apt update && apt upgrade -y" if "apt update && apt upgrade -y" in output else "Aucune tâche cron détectée"

    # Vérifier la présence du script cron `apt-compat` dans `/etc/cron.daily/`
    command_cron_scripts = "ls -1 /etc/cron.daily/ 2>/dev/null | grep -E '^apt-compat$' || echo 'Aucun script de mise à jour détecté'"
    stdin, stdout, stderr = serveur.exec_command(command_cron_scripts)
    output = stdout.read().decode().strip()
    update_status["Cron Scripts"] = "apt-compat" if "apt-compat" in output else "Aucun script de mise à jour détecté"

    # Vérifier si un timer systemd est configuré pour les mises à jour
    command_systemd_timer = "systemctl list-timers --all | grep -E 'apt-daily|apt-daily-upgrade'"
    stdin, stdout, stderr = serveur.exec_command(command_systemd_timer)
    output = stdout.read().decode().strip()
    update_status["Systemd Timer"] = "apt-daily.timer" if "apt-daily" in output else "Aucun timer systemd détecté"

    return update_status

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)

    print(f"Rapport généré : {output_path}")
