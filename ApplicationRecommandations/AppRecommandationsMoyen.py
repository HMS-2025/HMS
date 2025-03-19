import yaml
from Application.Thematiques.GestionAcces import apply_gestion_acces
from Application.Thematiques.Services import apply_services
from Application.Thematiques.Systeme import apply_systeme
from Application.Thematiques.Reseau import apply_reseau
# (Ajoute d'autres importations si tu as les autres thématiques plus tard)

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

# Fonction principale : application des corrections niveau moyen
def appliquer_correctifs_moyen(serveur):
    """Applique les correctifs de niveau moyen sur le serveur."""

    # Charger le rapport d'analyse produit précédemment
    rapport_analyse_path = "GenerationRapport/RapportAnalyse/analyse_moyen.yml"
    report_data = load_analysis_report(rapport_analyse_path)

    print("\n[Correction] Gestion des accès (niveau moyen)...")
    apply_gestion_acces(serveur, niveau="moyen", report_data=report_data)

    print("\n[Correction] Système (niveau moyen)...")
    apply_systeme(serveur, niveau="moyen", report_data=report_data)

    print("\n[Correction] Services (niveau moyen)...")
    apply_services(serveur, niveau="moyen", report_data=report_data)

    print("\n[Correction] Réseau (niveau moyen)...")
    apply_reseau(serveur, niveau="moyen", report_data=report_data)

    print("\n✅ Corrections terminées pour le niveau moyen.")

# Si besoin, une fonction pour appliquer les correctifs minimum/moyen en plus
# Exemple :
# def appliquer_correctifs_min(serveur): ...
# def appliquer_correctifs_moyen(serveur): ...
