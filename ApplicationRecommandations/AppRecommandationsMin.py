import yaml
from ApplicationRecommandations.Thematiques.GestionAcces import apply_access_management
from ApplicationRecommandations.Thematiques.PolitiqueMotDePasse import apply_password_policy
from ApplicationRecommandations.Thematiques.Maintenance import apply_maintenance
from ApplicationRecommandations.Thematiques.MiseAJour import apply_mise_a_jour
from ApplicationRecommandations.Thematiques.Systeme import apply_system


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

def application_recommandations_min (client) : 

    path_report="./GenerationRapport/RapportApplication/application_min.yml"
    report_data = load_analysis_report(path_report)

    print("\n[Correction] Gestion des accès (niveau min)...")
    apply_access_management(client, niveau="min", report_data=report_data)

    print("\n [Correction] Mot de passe ( niveau min) ")
    apply_password_policy(client, niveau="min", report_data=report_data)

    print("\n [Correction] Maintenance ( niveau min) ")
    apply_maintenance(client, niveau="min", report_data=report_data)

    print("\n [Correction] Mise à jour ( niveau moyen) ")
    apply_mise_a_jour(client, niveau="min", report_data=report_data)

    print("\n [Correction] System ( niveau moyen) ")
    apply_system(client, niveau="min", report_data=report_data)













"""def application_recommandations_min(client):
    Applique toutes les recommandations minimales à partir du rapport YAML
    path_report="./GenerationRapport/RapportApplication/"
    # Ici, on passe le chemin complet du fichier à chaque fonction sans vérification préalable
    apply_recommandation_acces(f"{path_report}/application.yml", client ,"min")
    apply_recommandation_mise_a_jour(f"{path_report}/application.yml", client , "min")
    apply_recommandation_politique_mot_de_passe(f"{path_report}/application.yml", client , "min")
    apply_recommandation_service(f"{path_report}/application.yml", client , "min")
    apply_recommandation_maintenance(f"{path_report}/application.yml", client , "min")
    apply_recommandation_reseau(f"{path_report}/application.yml", client , "min")
"""