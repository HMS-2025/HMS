import yaml
from datetime import datetime
import os

def extract_comments(yaml_path):
    comments = {}
    with open(yaml_path, "r", encoding="utf-8") as file:
        for line in file:
            if "#" in line:
                parts = line.split("#", 1)
                rule_id = parts[0].strip().rstrip(":")  # Récupération du rule_id sans ':'
                comment = parts[1].strip()  # Récupération du commentaire
                comments[rule_id] = comment
    return comments

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

            comments = extract_comments(yaml_path) 
            # Add a row for each rule
            section_html += f"""
            <tr class="{css_class}">
                <td>
                    <span class="tooltip">{rule_id}
                        <span class="tooltiptext">{comments.get(rule_id, 'No description available')}</span>
                    </span>
                </td>
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
                text-align: center;
            }}
            /* Top Banner */
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
            /* Styling for Analysis Level */
            .analysis-level {{
                text-align: center;
                font-size: 28px;
                font-weight: bold;
                color: #ffffff;
                background: linear-gradient(135deg, #004080, #007bff);
                padding: 20px;
                border-radius: 12px;
                margin: 25px auto;
                width: 50%;
                box-shadow: 4px 4px 15px rgba(0, 0, 0, 0.3);
                letter-spacing: 1.2px;
                text-transform: uppercase;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
                border: none;
                display: flex;
                justify-content: center;
                align-items: center;
            }}
            /* Tooltip Styling for Rule Comments */
            .tooltip {{
                position: relative;
                display: inline-block;
                cursor: pointer;
                font-weight: bold;
            }}

            .tooltip .tooltiptext {{
                visibility: hidden;
                width: 250px;
                background-color: rgba(0, 51, 102, 0.9);
                color: white;
                text-align: center;
                padding: 8px;
                border-radius: 6px;
                position: absolute;
                z-index: 10;
                bottom: 125%;
                left: 100%;  /* Place l'infobulle entièrement à droite */
                transform: translateX(10px); /* Décalage supplémentaire vers la droite */
                opacity: 0;
                transition: opacity 0.3s ease-in-out, left 0.3s ease-in-out;
                box-shadow: 2px 2px 10px rgba(0, 0, 0, 0.3);
                white-space: normal;
                max-width: 300px;
            }}

            /* Empêcher l'affichage hors écran */
            .tooltip .tooltiptext::after {{
               content: "";
                position: absolute;
                top: 50%;
                left: 0;
                transform: translateY(-50%);
                border-width: 8px;
                border-style: solid;
                border-color: transparent rgba(0, 51, 102, 0.9) transparent transparent;
            }}
            .tooltip:hover .tooltiptext {{
                visibility: visible;
                opacity: 1;
            }}
            /* Styling for Summary */
            .summary-title {{
                text-align: center;
                font-size: 22px;
                font-weight: bold;
                color: #003366;
                margin-top: 30px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            .report-header {{
                text-align: center;
                padding: 10px;
                background-color: white;
                border-bottom: 2px solid #003366;
            }}
            /* Summary Styling */
            .summary-section {{
                display: flex;
                justify-content: center;
                gap: 30px;
                margin: 30px 0;
            }}
            .summary-card {{
                background: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 4px 4px 15px rgba(0, 0, 0, 0.2);
                text-align: center;
                width: 220px;
                transition: transform 0.3s ease-in-out, box-shadow 0.3s ease-in-out;
            }}
            .summary-card:hover {{
                transform: scale(1.05);
                box-shadow: 6px 6px 20px rgba(0, 0, 0, 0.3);
            }}
            .rate {{
                font-size: 28px;
                font-weight: bold;
                color: #003366;
                margin-top: 5px;
            }}
            .compliant {{
                color: green;
            }}
            .non-compliant {{
                color: red;
            }}
            /* Table Styling */
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background-color: #003366;
                color: white;
            }}
            tr.compliant {{
                background-color: #c8e6c9; /* Light Green */
            }}
            tr.non-compliant {{
                background-color: #ffcdd2; /* Light Red */
            }}
            /* Report Date Styling */
            .report-date {{
                text-align: center;
                font-size: 18px;
                font-weight: bold;
                color: #003366;
                padding: 10px;
                background-color: #e3eaf4;
                border-radius: 5px;
                display: inline-block;
                margin: 20px auto;
            }}
            /* Footer Styling */
            .footer-links {{
                margin-top: 40px;
                font-size: 0.9em;
                text-align: center;
            }}
            .footer-links a {{
                color: #003366;
                text-decoration: none;
                margin-right: 20px;
            }}
            .footer-links a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="top-banner"></div>

        <div class="report-header">
            <h1>Hardening Magic Script - Official ANSSI Compliance Report</h1>
            <p style="font-style: italic;">Confidential - For authorized personnel only</p>
        </div>

        <div class="analysis-level">
            Analysis Level: <span style="font-weight: bold;">{niveau.capitalize()}</span>
        </div>
        <p class="report-date">Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <!-- Enhanced Summary Section -->
        <h3 class="summary-title">Summary</h3>
        <div class="summary-section">
            <div class="summary-card">
                <p><strong>Compliance Rate</strong></p>
                <p class="rate">{compliance_rate:.2f}%</p>
            </div>
            <div class="summary-card">
                <p><strong>Total Rules</strong></p>
                <p class="rate">{total_rules}</p>
            </div>
            <div class="summary-card">
                <p><strong>Compliant Rules</strong></p>
                <p class="rate compliant">{compliant_rules}</p>
            </div>
            <div class="summary-card">
                <p><strong>Non-Compliant Rules</strong></p>
                <p class="rate non-compliant">{total_rules - compliant_rules}</p>
            </div>
        </div>

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

    # Complete HTML content with professional design
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Hardening Magic Script - SSH Compliance Report</title>
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
            <h1>Hardening Magic Script - SSH Compliance Report</h1>
            <p style="font-style: italic;">Confidential - For authorized personnel only</p>
        </div>

        <h2>Analysis Level: SSH Compliance</h2>
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

    print(f"SSH HTML report generated : {html_path}")
