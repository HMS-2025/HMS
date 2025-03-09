from ApplicationRecommandations.Thematiques.GestionAcces import apply_recommandation_acces
from ApplicationRecommandations.Thematiques.Maintenance import apply_recommandation_maintenance
from ApplicationRecommandations.Thematiques.MiseAJour import apply_recommandation_mise_a_jour
from ApplicationRecommandations.Thematiques.PolitiqueMotDePasse import apply_recommandation_politique_mot_de_passe
from ApplicationRecommandations.Thematiques.Reseau import apply_recommandation_reseau_min
from ApplicationRecommandations.Thematiques.Services import apply_recommandation_service

def application_recommandations_min(client):
    """Applique toutes les recommandations minimales à partir du rapport YAML."""
    path_report="./GenerationRapport/RapportApplication/"
    # Ici, on passe le chemin complet du fichier à chaque fonction sans vérification préalable
    
    apply_recommandation_acces(f"{path_report}/application.yml", client ,"min")
    apply_recommandation_mise_a_jour(f"{path_report}/application.yml", client , "min")
    apply_recommandation_politique_mot_de_passe(f"{path_report}/application.yml", client , "min")
    apply_recommandation_service(f"{path_report}/application.yml", client , "min")
    apply_recommandation_maintenance(f"{path_report}/application.yml", client , "min")
    
    #apply_recommandation_reseau_min(f"{path_report}/reseau_minimal.yml", client)#verifier