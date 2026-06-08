import requests
import json
import pandas as pd
from datetime import datetime
import csv

today = datetime.now()
year = today.year
month = today.month

baseURL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/"
query = f"?$filter=releaseDate ge {year}-{month:02d}-01T00:00:00Z"
url = f"{baseURL}?{query}"
headers = {
    'Accept': 'application/json'
}

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise error if the request fails
    releaseNote = response.json()
    
    vulns = releaseNote.get("value", [])
    fields = ["CVE","Title","Severity","Impact","Exploited?","CVSSv3 Score","CVSS Vector","Release Date","Exploitability"]
    with open('output.csv', 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(fields)
            csvfile.close()
    #Leaving in case having a json is relevant. Uncomment below for the script also generate a json file.    
    """with open('data.json', 'w') as file:
        json.dump(releaseNote, file, indent=4)"""
    
    for vuln in vulns:
        results = []
        #Some field names may change or have incorrect information on MS's end. Leaving the variables for future troubleshooting just in case. 
        cve = vuln.get("cveNumber", "N/A")
        title = vuln.get("cveTitle", "N/A")
        severity = vuln.get("severity", "N/A")
        impact = vuln.get("impact", "N/A")
        release_date = vuln.get("releaseDate", "N/A")
        cvss_score = vuln.get("baseScore")
        cvss_vector = vuln.get("vectorString")
        exploitability = vuln.get("exploited", "N/A")
        latest_software_release = vuln.get("latestSoftwareRelease", "N/A")
        
        #Probably a more elegant way of doing this. Will look into it at a later date
        results.append(cve)
        results.append(title)
        results.append(severity)
        results.append(impact)
        results.append(exploitability)
        results.append(cvss_score)
        results.append(cvss_vector)
        results.append(release_date)
        results.append(latest_software_release)

        with open('output.csv', 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(results)

except requests.exceptions.RequestException as e:
    print(f"Error fetching updates from Microsoft API: {e}")
