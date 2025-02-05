import paramiko
import yaml
import os

# R61 - Effectuer des mises à jour régulières 
def analyse_mise_a_jour(serveur, niveau="min"):
    """Vérifie si les mises à jour automatiques sont bien configurées et génère un rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Vérification des mises à jour automatiques (R61)")
        report["update_status"] = get_check_auto_updates(serveur)
    
    save_yaml_report(report, "mise_a_jour_minimal.yml")
    print("Analyse terminée. Rapport généré : mise_a_jour_minimal.yml")

def get_check_auto_updates(serveur):
    try:
        update_status = {}

        # 1. Vérifier si unattended-upgrades est installé et activé
        command_unattended = "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed' && grep -E 'APT::Periodic::Unattended-Upgrade|APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/*"
        stdin, stdout, stderr = serveur.exec_command(command_unattended)
        update_status["Unattended Upgrades"] = stdout.read().decode().strip() or "Unattended-upgrades non activé"

        # 2. Vérifier la présence de tâches cron pour les mises à jour
        command_cron = "sudo crontab -l 2>/dev/null | grep -E 'apt-get upgrade|apt upgrade' || echo 'Aucune tâche cron détectée pour les mises à jour'"
        stdin, stdout, stderr = serveur.exec_command(command_cron)
        update_status["Cron Updates"] = stdout.read().decode().strip() or "Aucune tâche cron détectée pour les mises à jour"

        # 3. Vérifier si dnf-automatic est activé (pour les distributions basées sur Fedora, RHEL, CentOS)
        command_dnf = "systemctl is-enabled dnf-automatic 2>/dev/null"
        stdin, stdout, stderr = serveur.exec_command(command_dnf)
        update_status["DNF Automatic"] = stdout.read().decode().strip() or "dnf-automatic non activé"
        
        return update_status
    except Exception as e:
        print(f"Erreur lors de la vérification des mises à jour automatiques : {e}")
        return {}

def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    # Définir le chemin du dossier de sortie
    output_dir = "GenerationRapport/RapportAnalyse"
    
    # S'assurer que le dossier existe
    os.makedirs(output_dir, exist_ok=True)
    
    # Construire le chemin complet du fichier de sortie
    output_path = os.path.join(output_dir, output_file)
    
    # Écriture des données dans le fichier YAML
    with open(output_path, "w") as file:
        yaml.dump(data, file, default_flow_style=False)
    
    print(f"Rapport généré : {output_path}")