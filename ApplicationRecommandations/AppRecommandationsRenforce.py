import yaml
from ApplicationRecommandations.Thematiques.GestionAcces import apply_access_management
from ApplicationRecommandations.Thematiques.PolitiqueMotDePasse import apply_password_policy
from ApplicationRecommandations.Thematiques.Maintenance import apply_maintenance
from ApplicationRecommandations.Thematiques.MiseAJour import apply_mise_a_jour
from ApplicationRecommandations.Thematiques.Systeme import apply_system
from ApplicationRecommandations.Thematiques.Services import apply_services
from ApplicationRecommandations.Thematiques.JournalisationAudit import apply_logging


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

def application_recommandations_renf(client) : 

    path_report="./GenerationRapport/RapportApplication/application_renforce.yml"
    report_data = load_analysis_report(path_report)
    

    print("\n[Correction] Gestion des accès (niveau renforce)...")
    apply_access_management(client, niveau="renforce", report_data=report_data)

    print("\n [Correction] Mot de passe ( niveau renforce) ")
    apply_password_policy(client, niveau="renforce", report_data=report_data)

    print("\n [Correction] Maintenance ( niveau renforce) ")
    apply_maintenance(client, niveau="renforce", report_data=report_data)

    print("\n [Correction] Mise à jour ( niveau renforce) ")
    apply_mise_a_jour(client, niveau="renforce", report_data=report_data)

    print("\n [Correction] System ( niveau renforce) ")
    apply_system(client, niveau="renforce", report_data=report_data)

    print("\n [Correction] services ( niveau renforce) ")
    apply_services(client, niveau="renforce", report_data=report_data)

    print("\n [Correction] logging ( niveau renforce) ")
    apply_logging(client, niveau="renforce", report_data=report_data)

