import argparse
import json
import csv
from datetime import datetime

#Based on https://github.com/zaproxy/zaproxy/blob/296801bb838ae1ceca102a6be5b5ed2e8c29e097/src/org/parosproxy/paros/core/scanner/Alert.java#L62-L65
mapping_values = dict([
    ('0', 'Informational'),
    ('1', 'Low'),
    ('2','Medium'),
    ('3','High')
])

cwe_url = "https://cwe.mitre.org/data/definitions/{{cwe_id}}.html"
zap_url = "https://www.zaproxy.org/docs/alerts/{{alert_id}}/"

parser = argparse.ArgumentParser(description='Select file to parse.')
parser.add_argument('--file', dest='file',
                    default="zap-report.json",
                    help='Select rapidast file result to parse (default: zap-report.json)')

args = parser.parse_args()
f = open(args.file)
data = json.load(f)
alerts = data['site'][0]['alerts']
parsedalerts = []


for alert in alerts:
    risk = mapping_values[alert['riskcode']]
    name = alert['name']
    description = alert['desc']
    solution = alert['solution']
    cwe = cwe_url.replace('{{cwe_id}}', alert['cweid'])
    instances = alert['instances']
    parsed_instances = []
    for instance in instances:
        parsed_instances.append(instance['uri'])

    confidence = mapping_values[alert['confidence']]
    zap_alert = zap_url.replace('{{alert_id}}', alert['alertRef'])

    parsed_alert = [risk,name,description,solution,cwe,parsed_instances,confidence, zap_alert]
    parsedalerts.append(parsed_alert)


file_name = "parsed_results_" + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + ".csv"
with open(file_name, 'w', newline='') as file:
    writer = csv.writer(file)
    information = [data['site'][0]['@name'], "Port = " + data['site'][0]['@port'], "SSL = " + data['site'][0]['@ssl']]
    writer.writerow(information)
    field = ["Risk", "Name", "Description", "Solution", "CWE", "Affected Instances (Short form)", "Confidence", "Alert information"]
    writer.writerow(field)
    for elem in parsedalerts:
        writer.writerow(elem)
