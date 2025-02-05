from AnalyseConfiguration.Thematiques.GestionAcces import analyse_gestion_acces
from AnalyseConfiguration.Thematiques.Services import analyse_services
from AnalyseConfiguration.Thematiques.MiseAJour import analyse_mise_a_jour
from AnalyseConfiguration.Thematiques.PolitiqueMotDePasse import analyse_politique_mdp
from AnalyseConfiguration.Thematiques.Reseau import analyse_reseau
from AnalyseConfiguration.Thematiques.Maintenance import analyse_maintenance
from AnalyseConfiguration.Thematiques.JournalisationAudit import analyse_journalisation
from AnalyseConfiguration.Thematiques.Utilisateurs import analyse_utilisateurs

# Analyse SSH et analyse minimale
def analyse_min(serveur):
    """Exécute toutes les analyses du niveau minimal."""
    print("\n[Analyse] Gestion des accès...")
    analyse_gestion_acces(serveur, niveau="min")

    print("\n[Analyse] Services...")
    analyse_services(serveur, niveau="min")

    print("\n[Analyse] Mises à jour...")
    analyse_mise_a_jour(serveur, niveau="min")

    print("\n[Analyse] Politique de mot de passe...")
    analyse_politique_mdp(serveur, niveau="min")

    print("\n[Analyse] Réseau...")
    analyse_reseau(serveur, niveau="min")
    
    print("\n[Analyse] Maintenance...")
    analyse_maintenance(serveur, niveau="min")
    
    print("\n[Analyse] Journalisation et Audit...")
    analyse_journalisation(serveur, niveau="min")
    
    print("\n[Analyse] Utilisateurs...")
    analyse_utilisateurs(serveur, niveau="min")

    print("\n Analyse minimale terminée.")
