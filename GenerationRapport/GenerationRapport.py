import yaml
from datetime import datetime
import os

def generate_html_report(yaml_path, html_path, niveau):
    # Load YAML data
    with open(yaml_path, 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file)

    compliant_rules = 0
    total_rules = 0
    html_sections = ""

    # Iterate over each category (access_management, services, etc.)
    for category, rules in data.items():
        section_html = f"<h2>{category.capitalize()}</h2>"
        section_html += """
        <table>
            <tr>
                <th>Rule</th>
                <th>Status</th>
                <th>To Apply</th>
                <th>Detected Elements</th>
                <th>Expected Elements</th>
            </tr>
        """
        for rule_id, details in rules.items():
            total_rules += 1
            status = details.get('status', 'None').lower()  # Convert to lowercase for comparison
            apply = details.get('apply', False)
            detected = details.get("detected_elements", "None")
            expected = details.get("expected_elements", "None")

            if status == "compliant":
                compliant_rules += 1
                css_class = "compliant"
            else:
                css_class = "non-compliant"

            # Add a row for each rule
            section_html += f"""
                <tr class="{css_class}">
                    <td>{rule_id}</td>
                    <td>{status.capitalize()}</td>
                    <td>{"Yes" if apply else "No"}</td>
                    <td><pre>{yaml.dump(detected, allow_unicode=True)}</pre></td>
                    <td><pre>{yaml.dump(expected, allow_unicode=True)}</pre></td>
                </tr>
            """
        section_html += "</table>"
        html_sections += section_html

    compliance_rate = (compliant_rules / total_rules) * 100 if total_rules else 100

    # Complete HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ANSSI Compliance Report ({niveau.capitalize()})</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1, h2 {{ color: #003366; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 40px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #003366; color: white; }}
            .compliant {{ background-color: #c8e6c9; }}  /* Green for compliant */
            .non-compliant {{ background-color: #ffcdd2; }}  /* Red for non-compliant */
        </style>
    </head>
    <body>
        <h1>ANSSI Compliance Report - Level {niveau.capitalize()}</h1>
        <p>Report Date : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <h2>Summary</h2>
        <ul>
            <li><strong>Compliance Rate :</strong> {compliance_rate:.2f}%</li>
            <li><strong>Total Rules :</strong> {total_rules}</li>
            <li><strong>Compliant Rules :</strong> {compliant_rules}</li>
            <li><strong>Non-Compliant Rules :</strong> {total_rules - compliant_rules}</li>
        </ul>

        {html_sections}
    </body>
    </html>
    """

    # Ensure the directory exists
    os.makedirs(os.path.dirname(html_path), exist_ok=True)

    # Write the HTML file
    with open(html_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    print(f"HTML report generated : {html_path}")
