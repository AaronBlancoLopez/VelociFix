#!/usr/bin/env python3

import argparse
import time
import re
import requests
import json
import velociraptorQueryManager as vqm

from termcolor import colored
from simple_term_menu import TerminalMenu
from pprint import pprint
from pprint import PrettyPrinter
from docx import Document
from docx.shared import Pt
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from docx.enum.table import WD_ALIGN_VERTICAL

apiKey = "5c3e4e6f-5df1-40bc-b109-f670eb19e8fb"

# writes the apps information to a .docx file
def appsInfoToDOCX(doc, data):
    doc.add_page_break()
    doc.add_heading('Software Information', level=2)
    doc.add_paragraph("\n")
    # Add a table to the document
    table = doc.add_table(rows=1, cols=3)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Publisher'
    hdr_cells[1].text = 'Display Name'
    hdr_cells[2].text = 'Display Version'
    # Formatting header
    for cell in hdr_cells:
        for paragraph in cell.paragraphs:
            paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
            paragraph.alignment 
            paragraph.runs[0].bold = True
            paragraph.runs[0].font.size = Pt(12)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
    # Populate the table
    for sublist in data:
        for item in sublist:
            row_cells = table.add_row().cells
            row_cells[0].text = item.get('Publisher') or 'N/A'
            row_cells[1].text = item.get('DisplayName') or 'N/A'
            row_cells[2].text = item.get('DisplayVersion') or 'N/A'
            
            # Center the text in each cell
            for cell in row_cells:
                for paragraph in cell.paragraphs:
                    paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
                cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER


# writes client information to a .docx file
def clientInfoToDOCX(doc, json_data):
    for item in json_data:
        for key, value in item.items():
            doc.add_heading(key.replace('_', ' ').title(), level=2)
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, list):
                        doc.add_paragraph(f"{sub_key.replace('_', ' ').title()}:")
                        for sub_item in sub_value:
                            doc.add_paragraph(f"  - {sub_item}", style='List Bullet')
                    else:
                        doc.add_paragraph(f"{sub_key.replace('_', ' ').title()}: {sub_value}")
            else:
                doc.add_paragraph(f"{key.replace('_', ' ').title()}: {value}")
            doc.add_paragraph()


# retrieves the possible CPEs for a given app name and version
def find_cpes(name, version):
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    params = {
        "namingFormat": "2.3",
        "keyword": f"{name} {version}"
    }
    response = requests.get(base_url, params=params)
    content = response.text
    cpe_matches = re.findall(r'cpe:(.*?)<', content)
    return cpe_matches[0] if cpe_matches else None


# retrieves the CVE details for a given CPE
def fetch_cve_details(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = f"{base_url}?cpeName=cpe:{cpe_string}" 
    # NVD API rate limit is 5 requests every 30 seconds (50 if api key is given)
    time.sleep(6)
    response = requests.get(url)
    if response.status_code != 200:
        print(colored(f"Error: Unable to retrieve CVE data for CPE: {cpe_string}. Status code: {response.status_code}", "red"))
        return []
    try:
        data = response.json()
    except json.JSONDecodeError:
        print(colored(f"Error decoding JSON for CPE: {cpe_string}. Skipping.", "red"))
        return []
    if data["vulnerabilities"]:
        all_cve_details = []
        for cve_item in data["vulnerabilities"]:
            cve_id = cve_item["cve"]["id"]
            description_text = cve_item["cve"]["descriptions"][0]["value"]
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            weaknesses = []
            for problem_type in cve_item["cve"]["weaknesses"]:
                for description in problem_type["description"]:
                    weaknesses.append(description["value"])
            if cve_item.get("cve", {}).get("metrics", {}).get("cvssMetricV31") is not None:
                baseSeverity = cve_item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]    
                exploitabilityScore = cve_item["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"]
                impactScore = cve_item["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"]
            elif cve_item.get("cve", {}).get("metrics", {}).get("cvssMetricV2") is not None:
                baseSeverity = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                exploitabilityScore = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["exploitabilityScore"]
                impactScore = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"]
            all_cve_details.append({
                "CVE ID": cve_id,
                "Description": description_text,
                "Weaknesses": ", ".join(weaknesses),
                "Base severity": baseSeverity,
                "Exploitability score": exploitabilityScore,
                "Impact score": impactScore,
                "Link": link,
            })
        return all_cve_details
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str,
                        help='Path to the api_client config. You can generate such '
                        'a file with "velociraptor config api_client"')
    args = parser.parse_args()
    # main menu configuration
    main_menu_title = "  Main Menu.\n  Press Q or Esc to quit. \n"
    main_menu_items = ["See connected clients", "Scan client", "Third Item", "Quit"]
    main_menu_cursor = "> "
    main_menu_cursor_style = ("fg_red", "bold")
    main_menu_style = ("bg_red", "fg_yellow")
    main_menu_exit = False
    # main menu
    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        menu_cursor=main_menu_cursor,
        menu_cursor_style=main_menu_cursor_style,
        menu_highlight_style=main_menu_style,
        cycle_cursor=True,
        clear_screen=True,
    )
    # main menu loop
    while not main_menu_exit:
        main_sel = main_menu.show()
        # FIRST OPTION: lists all currently connected clients
        if main_sel == 0:
            print("List of currently connected clients:\n")
            for client in vqm.getClients(args.config):
                print("- " + client)
            input("\n\nPress Enter to go back to the main menu...")
        # SECOND OPTION: scan the apps installed in a client
        elif main_sel == 1:
            clients = vqm.getClients(args.config)
            print("Select a client to scan:\n")
            # client menu configuration
            client_menu = TerminalMenu(
                menu_entries=clients,
                title="Select a client to scan",
                menu_cursor=main_menu_cursor,
                menu_cursor_style=main_menu_cursor_style,
                menu_highlight_style=main_menu_style,
                cycle_cursor=True,
                clear_screen=True,
            )
            client_sel = client_menu.show()
            # .docx creation from JSON data
            doc = Document()
            doc.add_heading('Client Information Report', 0)
            # get and write client and apps information to the .docx file
            client_info = vqm.getClientInfo(args.config, clients[client_sel])
            apps = vqm.getApps(args.config, clients[client_sel])
            clientInfoToDOCX(doc, client_info)
            appsInfoToDOCX(doc, apps)
            client_abreviation = clients[client_sel].split(".")[1]
            doc.save(f"{client_abreviation}_Information_Report.docx")
            # remember 32 and 64 bit apps are separated
            apps_32 = apps[0]
            apps_64 = apps[1]
            print("List of installed applications:\n")
            # print the apps and search for possible CVEs
            max_name_length = max(len(app['DisplayName']) for app in apps_32 + apps_64)
            for app in apps_32:
                name = ' '.join(app['DisplayName'].split()[:2])
                version = app['DisplayVersion']
                if cpe := find_cpes(name, version):
                    cves = fetch_cve_details(cpe)
                    #pp.pprint(f"[!] Vulnerabilities found for {app['DisplayName']} {version}\n")
                    #pp.pprint(cves)
                    print(colored("- {:{}} {}".format(app['DisplayName'], max_name_length, version), "red"))
                    continue
                print("- {:{}} {}".format(app['DisplayName'], max_name_length, version))
            for app in apps_64:
                name = ' '.join(app['DisplayName'].split()[:2])
                version = app['DisplayVersion']
                if cpe := find_cpes(name, version):
                    cves = fetch_cve_details(cpe)
                    #pp.pprint(f"[!] Vulnerabilities found for {app['DisplayName']} {version}\n")
                    #pp.pprint(cves)
                    pprint(cves)
                    print(colored("- {:{}} {}".format(app['DisplayName'], max_name_length, version), "red"))
                    continue
                print("- {:{}} {}".format(app['DisplayName'], max_name_length, version))

            
            input("\n\nPress Enter to go back to the main menu...")

        # third option: do something else
        elif main_sel == 2:
            clients = vqm.getClients(args.config)
            print("Select a client to scan:\n")

            # client menu configuration
            client_menu = TerminalMenu(
                menu_entries=clients,
                title="Select a client to scan",
                menu_cursor=main_menu_cursor,
                menu_cursor_style=main_menu_cursor_style,
                menu_highlight_style=main_menu_style,
                cycle_cursor=True,
                clear_screen=True,
            )
            client_sel = client_menu.show()

            client_info = vqm.getClientInfo(args.config, clients[client_sel])

            # .docx creation from JSON data
            doc = Document()
            doc.add_heading('Client Information Report', 0)

            clientInfoToDOCX(doc, client_info)

            client_abreviation = clients[client_sel].split(".")[1]
            doc.save(f"{client_abreviation}_Information_Report.docx")

            input("\n\nPress Enter to go back to the main menu...")

        elif main_sel == 3:
            clients = vqm.getClients(args.config)
            print("Powershell: \n")

            # client menu configuration
            client_menu = TerminalMenu(
                menu_entries=clients,
                title="Select a client to scan",
                menu_cursor=main_menu_cursor,
                menu_cursor_style=main_menu_cursor_style,
                menu_highlight_style=main_menu_style,
                cycle_cursor=True,
                clear_screen=True,
            )
            client_sel = client_menu.show()
            response = vqm.powershell(args.config)[0]['Stdout']
            formatted_response = response.replace('\r\n', '\n')
            print(formatted_response)
            input("\n\nPress Enter to go back to the main menu...")

        elif main_sel == 4 or main_sel == None:
            main_menu_exit = True
            print("Quit Selected")



if __name__ == '__main__':
    main()