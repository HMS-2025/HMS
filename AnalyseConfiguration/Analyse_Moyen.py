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

# Charger les références depuis Reference_moyen.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_moyen.yaml"):
    """Charge le fichier Reference_moyen.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_moyen.yaml : {e}")
        return {}

# Analyse du niveau moyen avec conformité
def analyse_moyen(serveur):
    """Exécute toutes les analyses du niveau moyen en utilisant Reference_moyen.yaml."""
    
    # Charger les données de référence pour la conformité
    reference_data = load_reference_yaml()
    
    print("\n[Analyse] Gestion des accès (niveau moyen)...")
    analyse_gestion_acces(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analyse] Utilisateurs (niveau moyen)...")
    analyse_utilisateurs(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analyse] Système (niveau moyen)...")
    analyse_systeme(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analyse] Services (niveau moyen)...")
    analyse_services(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analyse] Mises à jour (niveau moyen)...")
    analyse_mise_a_jour(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analyse] Politique de mot de passe (niveau moyen)...")
    analyse_politique_mdp(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analyse] Réseau (niveau moyen)...")
    analyse_reseau(serveur, niveau="moyen", reference_data=reference_data)
    
    print("\n[Analyse] Maintenance (niveau moyen)...")
    analyse_maintenance(serveur, niveau="moyen", reference_data=reference_data)
    
    print("\n[Analyse] Journalisation et Audit (niveau moyen)...")
    analyse_journalisation(serveur, niveau="moyen", reference_data=reference_data)