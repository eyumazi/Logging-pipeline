import os
import yaml
import glob

RULES_DIR = "/app/rules"
OUTPUT_FILE = "/out/vmalert_rules.yml"

def parse_sigma_rule(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    rule_id = data.get('id', 'unknown')
    title = data.get('title', 'Unnamed Rule')
    level = data.get('level', 'info')
    
    detection = data.get('detection', {})
    selection = detection.get('selection', {})
    
    # Build LogsQL condition
    logsql_parts = []
    
    if isinstance(selection, dict):
        for key, val in selection.items():
            if 'event_id' in key:
                logsql_parts.append(f'event_id:="{val}"')
            elif 'message|contains' in key:
                if isinstance(val, list):
                    or_terms = ' OR '.join([f'message:"{term}"' for term in val])
                    logsql_parts.append(f'({or_terms})')
                else:
                    logsql_parts.append(f'message:"{val}"')
    
    logsql_query = " AND ".join(logsql_parts) if logsql_parts else '*'
    
    # Wrap in VictoriaLogs count query for VMAlert
    query = f'count_over_time(_time:5m {logsql_query}) > 0'
    
    return {
        'alert': title.replace(' ', '_'),
        'expr': query,
        'for': '0m',
        'labels': {
            'severity': level,
            'sigma_id': rule_id
        },
        'annotations': {
            'summary': title,
            'description': f'Sigma detection rule triggered: {title}'
        }
    }

def generate_vmalert_config():
    rules = []
    for filepath in glob.glob(os.path.join(RULES_DIR, "*.yml")):
        try:
            rule = parse_sigma_rule(filepath)
            rules.append(rule)
            print(f"Converted: {os.path.basename(filepath)}")
        except Exception as e:
            print(f"Failed to parse {filepath}: {e}")

    vm_config = {
        'groups': [
            {
                'name': 'sigma_rules_group',
                'rules': rules
            }
        ]
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(vm_config, f, default_flow_style=False)
    print(f"Successfully generated {len(rules)} VMAlert rules at {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_vmalert_config()