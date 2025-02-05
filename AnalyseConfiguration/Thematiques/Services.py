import paramiko
import yaml
import os

# R62 - Désactiver les services non nécessaires
def analyse_services(serveur, niveau="min"):
    """Analyse les services actifs et génère un rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Vérification des services non nécessaires (R62)")
        # La fonction pour récupérer les services non nécessaires n'est pas encore implémentée
        report["unnecessary_services"] = "Fonction non implémentée"
    
    save_yaml_report(report, "services_minimal.yml")
    print("Analyse terminée. Rapport généré : services_minimal.yml")

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