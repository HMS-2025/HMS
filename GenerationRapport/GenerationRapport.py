import yaml
from datetime import datetime
import os

def generate_html_report(yaml_path, html_path, niveau):
    # Chargement du YAML
    with open(yaml_path, 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file)

    compliant_rules = 0
    total_rules = 0
    html_sections = ""

    # Parcourir chaque catégorie (gestion_acces, services, etc.)
    for category, rules in data.items():
        section_html = f"<h2>{category.capitalize()}</h2>"
        section_html += """
        <table>
            <tr>
                <th>Règle</th>
                <th>Status</th>
                <th>À appliquer</th>
                <th>Éléments détectés</th>
                <th>Éléments attendus</th>
            </tr>
        """
        for rule_id, details in rules.items():
            total_rules += 1
            status = details.get('status', 'N/A')
            apply = details.get('apply', False)
            detected = details.get("éléments_detectés", details.get("detected_elements", "N/A"))
            expected = details.get("éléments_attendus", details.get("expected_elements", "N/A"))


            if status.lower().startswith('conforme'):
                compliant_rules += 1
                css_class = "compliant"
            else:
                css_class = "non-compliant"

            # Ajouter une ligne par règle
            section_html += f"""
                <tr class="{css_class}">
                    <td>{rule_id}</td>
                    <td>{status}</td>
                    <td>{"Oui" if apply else "Non"}</td>
                    <td><pre>{yaml.dump(detected, allow_unicode=True)}</pre></td>
                    <td><pre>{yaml.dump(expected, allow_unicode=True)}</pre></td>
                </tr>
            """
        section_html += "</table>"
        html_sections += section_html

    compliance_rate = (compliant_rules / total_rules) * 100 if total_rules else 100

    # Contenu HTML complet
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport de Conformité ANSSI ({niveau.capitalize()})</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1, h2 {{ color: #003366; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 40px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #003366; color: white; }}
            .compliant {{ background-color: #c8e6c9; }}
            .non-compliant {{ background-color: #ffcdd2; }}
        </style>
    </head>
    <body>
        <h1>Rapport de Conformité ANSSI - Niveau {niveau.capitalize()}</h1>
        <p>Date du rapport : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <h2>Résumé</h2>
        <ul>
            <li><strong>Taux de conformité :</strong> {compliance_rate:.2f}%</li>
            <li><strong>Règles totales :</strong> {total_rules}</li>
            <li><strong>Règles conformes :</strong> {compliant_rules}</li>
            <li><strong>Règles non conformes :</strong> {total_rules - compliant_rules}</li>
        </ul>

        {html_sections}
    </body>
    </html>
    """

    # Assurer la création du dossier
    os.makedirs(os.path.dirname(html_path), exist_ok=True)

    # Écriture du fichier HTML
    with open(html_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    print(f"Rapport HTML généré : {html_path}")
