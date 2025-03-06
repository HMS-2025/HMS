from ApplicationRecommandations.Thematiques.GestionAcces import apply_recommandation_acces
from ApplicationRecommandations.Thematiques.Maintenance import apply_recommandation_maintenance_min
from ApplicationRecommandations.Thematiques.MiseAJour import apply_recommandation_mise_a_jour
from ApplicationRecommandations.Thematiques.PolitiqueMotDePasse import apply_recommandation_politique_mot_de_passe_min
from ApplicationRecommandations.Thematiques.Reseau import apply_recommandation_reseau_min
from ApplicationRecommandations.Thematiques.Services import apply_recommandation_service_min

def application_recommandations_min(client):
    """Applique toutes les recommandations minimales à partir du rapport YAML."""
    path_report="./GenerationRapport/RapportApplication/"
    # Ici, on passe le chemin complet du fichier à chaque fonction sans vérification préalable
    apply_recommandation_acces(f"{path_report}/application_min.yml", client)
    apply_recommandation_mise_a_jour(f"{path_report}/mise_a_jour_minimal.yml", client)
    #apply_recommandation_politique_mot_de_passe_min(f"{path_report}/politique_mdp_minimal.yml", client) #verifier aussi
    #apply_recommandation_reseau_min(f"{path_report}/reseau_minimal.yml", client)#verifier
    #apply_recommandation_maintenance_min(f"{path_report}/application_min.yml", client) #verifier
    #apply_recommandation_service_min(f"{path_report}/services_minimal.yml", client)#verifier