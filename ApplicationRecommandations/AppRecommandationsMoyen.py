import yaml
from ApplicationRecommandations.Thematiques.GestionAcces import apply_gestion_acces

# Fonction de chargement des rapports d'analyse
def load_analysis_report(file_path):
    """Charge le rapport d'analyse YAML existant."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            analysis_report = yaml.safe_load(file)
        return analysis_report
    except Exception as e:
        print(f"Erreur lors du chargement du rapport d'analyse {file_path} : {e}")
        return {}

def application_recommandations_moyen (client) : 

    path_report="./GenerationRapport/RapportApplication/application_moyen.yml"
    report_data = load_analysis_report(path_report)
    

    print("\n[Correction] Gestion des accès (niveau moyen)...")
    apply_gestion_acces(client, niveau="moyen", report_data=report_data)

    print("\n Corrections terminées pour le niveau moyen.")
