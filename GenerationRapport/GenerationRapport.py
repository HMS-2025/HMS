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

 # Complete HTML content with professional design
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Hardening Magic Script - ANSSI Compliance Report (Level {niveau.capitalize()})</title>
        <style>
            /* Main Styling */
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                background-color: #f4f4f4;
            }}
            h1, h2 {{
                color: #003366;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 40px;
                background: white;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #003366;
                color: white;
            }}
            .compliant {{
                background-color: #c8e6c9;
            }}
            .non-compliant {{
                background-color: #ffcdd2;
            }}
            .footer-links {{
                margin-top: 40px;
                font-size: 0.9em;
            }}
            .footer-links a {{
                color: #003366;
                text-decoration: none;
                margin-right: 20px;
            }}
            .footer-links a:hover {{
                text-decoration: underline;
            }}
            
            /* Top Banner with Small Squares */
            .top-banner {{
                background: repeating-linear-gradient(
                    45deg,
                    #f8f9fa,
                    #f8f9fa 10px,
                    #d6d6d6 10px,
                    #d6d6d6 20px
                );
                height: 50px;
                width: 100%;
            }}

            .report-header {{
                text-align: center;
                padding: 10px;
                background-color: white;
                border-bottom: 2px solid #003366;
            }}
        </style>
    </head>
    <body>
        <div class="top-banner"></div>

        <div class="report-header">
            <h1>Hardening Magic Script - Official ANSSI Compliance Report</h1>
            <p style="font-style: italic;">Confidential - For authorized personnel only</p>
        </div>

        <h2>Analysis Level: {niveau.capitalize()}</h2>
        <p><strong>Report Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <h3>Summary</h3>
        <ul>
            <li><strong>Compliance Rate :</strong> {compliance_rate:.2f}%</li>
            <li><strong>Total Rules :</strong> {total_rules}</li>
            <li><strong>Compliant Rules :</strong> {compliant_rules}</li>
            <li><strong>Non-Compliant Rules :</strong> {total_rules - compliant_rules}</li>
        </ul>

        {html_sections}

        <div class="footer-links">
            <p><strong>References & Links:</strong></p>
            <p>
                <a href="https://github.com/HMS-2025/HMS" target="_blank">HMS GitHub Project</a>
                <a href="https://cyber.gouv.fr/sites/default/files/document/fr_np_linux_configuration-v2.0.pdf" target="_blank">ANSSI Linux Guide</a>
                <a href="https://cyber.gouv.fr/sites/default/files/2014/01/NT_OpenSSH.pdf" target="_blank">ANSSI OpenSSH Guide</a>
            </p>
        </div>
    </body>
    </html>
    """

    # Ensure the directory exists
    os.makedirs(os.path.dirname(html_path), exist_ok=True)

    # Write the HTML file
    with open(html_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    print(f"HTML report generated : {html_path}")

def generate_ssh_html_report(yaml_path, html_path):
    """
    Generates a separate HTML report for SSH compliance.
    """
    with open(yaml_path, 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file)

    compliant_rules = 0
    total_rules = 0
    html_sections = ""

    # Ensure ssh_compliance exists in YAML
    rules = data.get("ssh_compliance", {})

    section_html = "<h2>SSH Compliance</h2>"
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
        status = details.get('status', 'None').lower()
        apply = details.get('apply', False)
        detected = details.get("detected_elements", "None")
        expected = details.get("expected_elements", "None")

        if status.startswith("compliant"):
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
        <title>SSH Compliance Report</title>
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
        <h1>SSH Compliance Report</h1>
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

    print(f"SSH HTML report generated : {html_path}")
