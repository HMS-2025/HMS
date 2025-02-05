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