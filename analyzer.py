import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:7b"

def load_cloudtrail_log(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)
    return data.get("Records", [])

def analyze_event(event):
    prompt = f"""You are a SOC analyst reviewing an AWS CloudTrail event.
Analyze the following event and respond in this exact format:

SEVERITY: [LOW / MEDIUM / HIGH / CRITICAL]
SUMMARY: [one sentence explaining what happened]
SUSPICION: [why this may or may not be suspicious]
MITRE_TECHNIQUE: [relevant MITRE ATT&CK technique if applicable, else None]
RECOMMENDED_ACTION: [what a SOC analyst should do]

CloudTrail Event:
{json.dumps(event, indent=2)}
"""
    response = requests.post(OLLAMA_URL, json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    })
    return response.json().get("response", "No response")

def run_analysis(log_path):
    events = load_cloudtrail_log(log_path)
    results = []
    print(f"\n Analyzing {len(events)} events...\n")
    for i, event in enumerate(events):
        print(f"Analyzing event {i+1}/{len(events)}: {event.get('eventName', 'Unknown')}")
        analysis = analyze_event(event)
        results.append({
            "eventName": event.get("eventName"),
            "eventTime": event.get("eventTime"),
            "sourceIPAddress": event.get("sourceIPAddress"),
            "userIdentity": event.get("userIdentity", {}).get("type"),
            "analysis": analysis
        })
    return results
def save_report(results, output_path="report.txt"):
    with open(output_path, "w") as f:
        f.write("="*60 + "\n")
        f.write("AI-POWERED CLOUDTRAIL ANOMALY DETECTION REPORT\n")
        f.write("="*60 + "\n\n")
        
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        
        for r in results:
            f.write(f"Event: {r['eventName']} | Time: {r['eventTime']}\n")
            f.write(f"Source IP: {r['sourceIPAddress']} | Identity: {r['userIdentity']}\n")
            f.write(f"\n{r['analysis']}\n")
            f.write("-"*60 + "\n\n")
            
            for severity in severity_counts:
                if severity in r['analysis']:
                    severity_counts[severity] += 1
                    break
        
        f.write("="*60 + "\n")
        f.write("SUMMARY\n")
        f.write("="*60 + "\n")
        f.write(f"Total Events Analyzed: {len(results)}\n")
        for severity, count in severity_counts.items():
            f.write(f"{severity}: {count}\n")
    
    print(f"\n Report saved to {output_path}")

if __name__ == "__main__":
    log_file = "logs/cloudtrail.json"
    results = run_analysis(log_file)
    
    for r in results:
        print("\n" + "="*60)
        print(f"Event: {r['eventName']} | Time: {r['eventTime']}")
        print(f"Source IP: {r['sourceIPAddress']} | Identity: {r['userIdentity']}")
        print(f"\n{r['analysis']}")
    
    save_report(results)