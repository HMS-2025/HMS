import yaml
from AnalyseConfiguration.Thematiques.GestionAcces import analyse_gestion_acces
from AnalyseConfiguration.Thematiques.Services import analyse_services
from AnalyseConfiguration.Thematiques.MiseAJour import analyse_mise_a_jour
from AnalyseConfiguration.Thematiques.PolitiqueMotDePasse import analyse_politique_mdp
from AnalyseConfiguration.Thematiques.Reseau import analyse_reseau
from AnalyseConfiguration.Thematiques.Maintenance import analyse_maintenance
from AnalyseConfiguration.Thematiques.JournalisationAudit import analyse_journalisation
from AnalyseConfiguration.Thematiques.Utilisateurs import analyse_utilisateurs
from AnalyseConfiguration.Thematiques.Systeme import analyse_systeme

# Charger les références depuis Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    """Charge le fichier Reference_min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        # to
        print(f"Erreur lors du chargement de Reference_min.yaml : {e}")
        return {}

# Analyse du niveau minimal avec conformité
def analyse_min(serveur):
    """Exécute toutes les analyses du niveau minimal en utilisant Reference_min.yaml."""
    
    # Charger les données de référence pour la conformité
    reference_data = load_reference_yaml()
    
    print("\n[Analyse] Gestion des accès...")
    analyse_gestion_acces(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analyse] Services...")
    analyse_services(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analyse] Mises à jour...")
    analyse_mise_a_jour(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analyse] Politique de mot de passe...")
    analyse_politique_mdp(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analyse] Réseau...")
    analyse_reseau(serveur, niveau="min", reference_data=reference_data)
    
    print("\n[Analyse] Maintenance...")
    analyse_maintenance(serveur, niveau="min", reference_data=reference_data)
    
    print("\n[Analyse] Journalisation et Audit...")
    analyse_journalisation(serveur, niveau="min", reference_data=reference_data)
    
    print("\n[Analyse] Utilisateurs...")
    analyse_utilisateurs(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analyse] Système...")
    analyse_systeme(serveur, niveau="min", reference_data=reference_data)
