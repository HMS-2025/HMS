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

# Load references from Reference_renforce.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_renforce.yaml"):
    """Load Reference_renforce.yaml and return its contents."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Error loading Reference_renforce.yaml: {e}")
        return {}

def analyse_renforce(serveur):
    """Perform all reinforced level analyses using Reference_renforce.yaml."""
    
    reference_data = load_reference_yaml()
    
    print("\n[Analysis] Access Management (reinforced level)...")
    analyse_gestion_acces(serveur, niveau="renforce", reference_data=reference_data)

    print("\n[Analysis] Users (reinforced level)...")
    analyse_utilisateurs(serveur, niveau="renforce", reference_data=reference_data)

    print("\n[Analysis] System (reinforced level)...")
    analyse_systeme(serveur, niveau="renforce", reference_data=reference_data)

    print("\n[Analysis] Services (reinforced level)...")
    analyse_services(serveur, niveau="renforce", reference_data=reference_data)

    print("\n[Analysis] Updates (reinforced level)...")
    analyse_mise_a_jour(serveur, niveau="renforce", reference_data=reference_data)

    print("\n[Analysis] Password policy (reinforced level)...")
    analyse_politique_mdp(serveur, niveau="renforce", reference_data=reference_data)

    print("\n[Analysis] Network (reinforced level)...")
    analyse_reseau(serveur, niveau="renforce", reference_data=reference_data)
    
    print("\n[Analysis] Maintenance (reinforced level)...")
    analyse_maintenance(serveur, niveau="renforce", reference_data=reference_data)
    
    print("\n[Analysis] Logging and Audit (reinforced level)...")
    analyse_journalisation(serveur, niveau="renforce", reference_data=reference_data)
