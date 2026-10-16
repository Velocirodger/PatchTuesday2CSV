import requests
import json
from datetime import datetime
import csv

today = datetime.now()
year = today.year
month = today.month

baseURL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/"
skip = 0
url = f"{baseURL}?&offset=0&index=0&$skip={skip}"
headers = {
    'Accept': 'application/json',
    
}
counter = 0
vulns = []
try:
    response = requests.get(url, headers=headers)
    releaseNote = response.json()
    vulns.extend(releaseNote.get("value", []))
    counter += len(vulns)
    skip += 500
    url = f"{baseURL}?{query}&offset=0&index=0&$skip={skip}"
    while counter < 3000:
        response = requests.get(url, headers=headers)
        vulns.extend(response.json().get("value", []))
        counter += len(vulns)
        skip += 500
        url = f"{baseURL}?{query}&offset=0&index=0&$skip={skip}"

    fields = ["CVE","Title","Severity","Impact","Exploited?","CVSSv3 Score","CVSS Vector","Release Date","Exploitability", "Link"]
    with open('output.csv', 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(fields)
            csvfile.close()
    #Leaving in case having a json is relevant. Uncomment below for the script also generate a json file.    
    #with open('data.json', 'w') as file:
    #    json.dump(releaseNote, file, indent=4)
    
    for vuln in vulns:
        results = []

        if vuln.get("releaseNumber", "N/A") == f"{year}-{today.strftime("%b")}":
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
            
            results.append(cve)
            results.append(title)
            results.append(severity)
            results.append(impact)
            results.append(exploitability)
            results.append(cvss_score)
            results.append(cvss_vector)
            results.append(release_date)
            results.append(latest_software_release)
            results.append(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}")

            with open('output.csv', 'a', newline='', encoding='utf-8') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(results)

except requests.exceptions.RequestException as e:
    print(f"Error fetching updates from Microsoft API: {e}")
