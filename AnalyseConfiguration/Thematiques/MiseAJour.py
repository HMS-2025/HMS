import paramiko
import yaml
import os

# Charger les références depuis Reference_Min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_Min.yaml"):
    """Charge le fichier Reference_Min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_Min.yaml : {e}")
        return {}

# Comparer les résultats de l'analyse avec les références
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si une règle est conforme en la comparant avec Reference_Min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    non_compliant_items = {}

    # Comparer chaque sous-règle pour la mise à jour automatique
    for key, expected in expected_value.items():
        detected = rule_value.get(key, "Non détecté")
        
        # Vérification spécifique pour Systemd Timer
        if key == "Systemd Timer":
            if "apt-daily.timer" in detected and "apt-daily-upgrade.timer" in detected:
                detected = "Présent"
        
        if detected != expected:
            non_compliant_items[key] = {
                "Détecté": detected,
                "Attendu": expected
            }

    return {
        "status": "Non conforme" if non_compliant_items else "Conforme",
        "éléments_problématiques": non_compliant_items if non_compliant_items else "Aucun",
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

    # Affichage des résultats
    print("\n[Résultats de la conformité]")
    for rule, status in report.items():
        print(f"- {rule}: {status['status']}")
        if status["status"] == "Non conforme":
            print(f"  -> Éléments problématiques : {status['éléments_problématiques']}")
            print(f"  -> Éléments attendus : {status['éléments_attendus']}")

    print(f"\nTaux de conformité du niveau minimal (Mises à jour) : {compliance_percentage:.2f}%")

# R61 - Vérifier l'état des mises à jour automatiques
def get_check_auto_updates(serveur):
    """Vérifie la configuration des mises à jour automatiques sur le serveur."""
    try:
        update_status = {}

        # 1. Vérifier si unattended-upgrades est installé et activé
        command_unattended = (
            "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed' "
            "&& grep -E 'APT::Periodic::Unattended-Upgrade|APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/*"
        )
        stdin, stdout, stderr = serveur.exec_command(command_unattended)
        unattended_upgrades = stdout.read().decode().strip()
        update_status["Unattended Upgrades"] = "install ok installed" if unattended_upgrades else "Unattended-upgrades non activé"

        # 2. Vérifier la présence de tâches cron pour les mises à jour
        command_cron = (
            "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'Aucune tâche cron détectée'"
        )
        stdin, stdout, stderr = serveur.exec_command(command_cron)
        cron_updates = stdout.read().decode().strip()
        update_status["Cron Updates"] = "Présent" if "apt" in cron_updates else "Aucune tâche cron détectée"

        # 3. Vérifier les tâches cron système (dans /etc/cron.daily, weekly, monthly)
        command_cron_scripts = "ls -1 /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null | grep -E 'apt|unattended-upgrades'"
        stdin, stdout, stderr = serveur.exec_command(command_cron_scripts)
        cron_script_updates = stdout.read().decode().strip()
        update_status["Cron Scripts"] = "Présent" if cron_script_updates else "Aucun script de mise à jour détecté"

        # 4. Vérifier si un timer systemd est configuré pour les mises à jour
        command_systemd_timer = "systemctl list-timers --all | grep -E 'apt-daily|apt-daily-upgrade'"
        stdin, stdout, stderr = serveur.exec_command(command_systemd_timer)
        systemd_timer = stdout.read().decode().strip()
        update_status["Systemd Timer"] = "Présent" if "apt-daily.timer" in systemd_timer and "apt-daily-upgrade.timer" in systemd_timer else "Aucun timer systemd détecté"

        # 5. Vérifier si dnf-automatic est activé (pour Fedora, RHEL, CentOS)
        command_dnf = "systemctl is-enabled dnf-automatic 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command_dnf)
        dnf_automatic = stdout.read().decode().strip()
        update_status["DNF Automatic"] = "activé" if dnf_automatic == "enabled" else "dnf-automatic non activé"

        return update_status

    except Exception as e:
        print(f"Erreur lors de la vérification des mises à jour automatiques : {e}")
        return {}

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")
