import paramiko
import yaml
import os

def analyse_maintenance(serveur, niveau="min", reference_data=None):
    """Analyse la maintenance du système et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des paquets installés (R58)")
        installed_packages = check_installed_packages(serveur, reference_data)
        report["R58"] = check_compliance("R58", {"unnecessary_packages": installed_packages}, reference_data)

        print("-> Vérification des dépôts de paquets de confiance (R59)")
        trusted_repositories = check_trusted_repositories(serveur)
        report["R59"] = check_compliance("R59", {"trusted_repositories": trusted_repositories}, reference_data)
        save_yaml_report(report, "maintenance_minimal.yaml")
    
    if niveau == "moyen":
        print("-> Vérification du mot de passe GRUB 2/GNU (R5)")
        grub_password_status = check_grub_password(serveur)
        report["R5"] = grub_password_status
        save_yaml_report(report, "maintenance_intermediaire.yaml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau minimal (Maintenance) : {compliance_percentage:.2f}%")
    
    return report

# R5 - Vérifier qu'un mot de passe GRUB est mis en place
def check_grub_password(serveur):
    """Vérifie directement si un mot de passe GRUB 2 est configuré sur la machine."""
    command_check_grub_cfg = "grep -E 'set\\s+superusers' /etc/grub.d/* /boot/grub/grub.cfg"
    command_check_password = "grep -E 'password_pbkdf2' /etc/grub.d/* /boot/grub/grub.cfg"
    
    stdin, stdout, stderr = serveur.exec_command(command_check_grub_cfg)
    superusers_output = stdout.read().decode().strip()
    
    stdin, stdout, stderr = serveur.exec_command(command_check_password)
    password_output = stdout.read().decode().strip()
    
    if superusers_output and password_output:
        return {"status": "Conforme", "message": "Un mot de passe GRUB 2 est bien configuré."}
    else:
        return {"status": "Non conforme", "message": "Aucun mot de passe GRUB 2 détecté. Veuillez le configurer."}

# R58 - N’installer que les paquets strictement nécessaires
def check_installed_packages(serveur, reference_data):
    """Récupère la liste des paquets installés et identifie ceux qui sont non nécessaires en fonction de Reference_Min.yaml."""
    expected_packages = reference_data.get("R58", {}).get("expected", [])

    command = "dpkg --get-selections | grep -v deinstall"
    stdin, stdout, stderr = serveur.exec_command(command)
    installed_packages = stdout.read().decode().strip().split("\n")

    unnecessary_packages = [pkg.split()[0] for pkg in installed_packages if pkg.split()[0] not in expected_packages]
    return unnecessary_packages if unnecessary_packages else "Aucun paquet non nécessaire détecté"

# R59 - Utiliser des dépôts de paquets de confiance
def check_trusted_repositories(serveur):
    """Vérifie les dépôts de paquets configurés sur le système."""
    command = "grep -E '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null"
    stdin, stdout, stderr = serveur.exec_command(command)
    repositories = stdout.read().decode().strip().split("\n")
    return repositories if repositories else "Aucun dépôt détecté"

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)

    print(f"Rapport généré : {output_path}")
