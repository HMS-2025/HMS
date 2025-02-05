import subprocess
import yaml
import os

def analyse_journalisation(serveur, niveau="min"):
    """Analyse la journalisation et l'audit en fonction du niveau spécifié et génère un unique rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Aucune fonction pour le niveau minimal.")
    
    save_yaml_report(report, "journalisation_audit_minimal.yml")
    print(f"Analyse terminée. Rapport généré : journalisation_audit_minimal.yml")

# Aucune fonction pour le niveau min

def analyse_maintenance(serveur, niveau="min"):
    """Analyse la maintenance du système en fonction du niveau spécifié et génère un unique rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Vérification des paquets installés (R58)")
        report["unnecessary_packages"] = check_installed_packages()
        
        print("-> Vérification des dépôts de paquets de confiance (R59)")
        report["trusted_repositories"] = check_trusted_repositories()
    
    save_yaml_report(report, "maintenance_minimal.yml")
    print(f"Analyse terminée. Rapport généré : maintenance_minimal.yml")

# R58 - N’installer que les paquets strictement nécessaires
def check_installed_packages():
    necessary_packages = [
        'openssh-server',
        'curl',
        'vim',
    ]
    command = "dpkg --get-selections | grep -v deinstall"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    installed_packages = result.stdout.splitlines()
    unnecessary_packages = [pkg.split()[0] for pkg in installed_packages if pkg.split()[0] not in necessary_packages]
    return unnecessary_packages

# R59 - Utiliser des dépôts de paquets de confiance
def check_trusted_repositories():
    command = "grep -E '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    repositories = result.stdout.strip().split("\n")
    return repositories

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