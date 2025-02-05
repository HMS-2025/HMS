import paramiko
import yaml
import os

def analyse_reseau(serveur, niveau="min"):
    """Analyse la configuration réseau et génère un rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Vérification des services réseau actifs (R80)")
        report["active_services"] = get_active_services(serveur)
    
    save_yaml_report(report, "reseau_minimal.yml")
    print("Analyse terminée. Rapport généré : reseau_minimal.yml")

# R80 - Réduire la surface d’attaque des services réseau
def get_active_services(serveur):
    try:
        command_services = "sudo netstat -tulnp | awk '{print $1, $4, $7}'"
        stdin, stdout, stderr = serveur.exec_command(command_services)
        active_services = stdout.read().decode().strip()
        return active_services if active_services else "Aucun service réseau actif détecté"
    except Exception as e:
        print(f"Erreur lors de la récupération des services réseau actifs : {e}")
        return "Erreur"

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