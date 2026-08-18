import os
import glob
import yaml


RULES_DIR = "/app/rules"
OUTPUT_FILE = "/vmalert/generated_rules/vmalert_rules.yml"


def quote_logsqli_value(value):
    """
    Safely quote a value for LogsQL.
    """
    value = str(value)
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value}"'


def build_contains_filter(field, value):
    """
    Convert Sigma field|contains into a VictoriaLogs filter.
    """
    if isinstance(value, list):
        filters = []

        for item in value:
            filters.append(
                f'{field}:{quote_logsqli_value(item)}'
            )

        return "(" + " OR ".join(filters) + ")"

    return f'{field}:{quote_logsqli_value(value)}'


def build_selection(selection):
    """
    Convert one Sigma selection dictionary into LogsQL.
    """

    if not isinstance(selection, dict):
        return "*"

    filters = []

    for key, value in selection.items():

        # event_id
        if key == "event_id":
            if isinstance(value, list):
                values = [
                    f'event_id:={quote_logsqli_value(v)}'
                    for v in value
                ]

                filters.append(
                    "(" + " OR ".join(values) + ")"
                )

            else:
                filters.append(
                    f'event_id:={quote_logsqli_value(value)}'
                )

        # message|contains
        elif key == "message|contains":
            filters.append(
                build_contains_filter("message", value)
            )

        # Generic |contains support
        elif "|contains" in key:
            field = key.split("|", 1)[0]

            filters.append(
                build_contains_filter(field, value)
            )

        # Generic exact field
        else:
            if isinstance(value, list):
                values = [
                    f'{key}:={quote_logsqli_value(v)}'
                    for v in value
                ]

                filters.append(
                    "(" + " OR ".join(values) + ")"
                )

            else:
                filters.append(
                    f'{key}:={quote_logsqli_value(value)}'
                )

    if not filters:
        return "*"

    return " AND ".join(filters)


def build_condition(detection):
    """
    Convert Sigma detection selections + condition
    into LogsQL.
    """

    condition = detection.get("condition", "selection")

    selections = {
        key: value
        for key, value in detection.items()
        if key != "condition"
    }

    # Simple condition:
    # condition: selection
    if condition == "selection":
        selection = selections.get("selection", {})

        return build_selection(selection)

    # Handle:
    # selection1 and selection2
    if " and " in condition.lower():

        parts = [
            part.strip()
            for part in condition.lower().split(" and ")
        ]

        expressions = []

        for part in parts:
            original_key = next(
                (
                    key for key in selections
                    if key.lower() == part
                ),
                None
            )

            if original_key:
                expressions.append(
                    build_selection(selections[original_key])
                )

        if expressions:
            return " AND ".join(expressions)

    # Handle:
    # selection1 or selection2
    if " or " in condition.lower():

        parts = [
            part.strip()
            for part in condition.lower().split(" or ")
        ]

        expressions = []

        for part in parts:
            original_key = next(
                (
                    key for key in selections
                    if key.lower() == part
                ),
                None
            )

            if original_key:
                expressions.append(
                    build_selection(selections[original_key])
                )

        if expressions:
            return "(" + " OR ".join(expressions) + ")"

    raise ValueError(
        f"Unsupported Sigma condition: {condition}"
    )


def parse_sigma_rule(file_path):

    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("Sigma rule is not a YAML mapping")

    rule_id = data.get("id", "unknown")
    title = data.get("title", "Unnamed Rule")
    level = data.get("level", "info")

    detection = data.get("detection", {})

    if not detection:
        raise ValueError("Missing detection section")

    # Convert Sigma detection into raw LogsQL
    filter_expression = build_condition(detection)

    # Raw LogsQL pipeline without logs(...) wrapper
    query = (
        f'{filter_expression} '
        f'| stats count() as matches '
        f'| filter matches:>0'
    )

    alert_name = (
        title
        .replace(" ", "_")
        .replace("-", "_")
    )

    return {
        "alert": alert_name,
        "expr": query,
        "for": "0m",

        "labels": {
            "severity": level,
            "sigma_id": rule_id
        },

        "annotations": {
            "summary": title,
            "description": (
                f"Sigma detection rule triggered: {title}"
            )
        }
    }


def generate_vmalert_config():

    rules = []

    # Read every individual .yml/.yaml file
    files = (
        glob.glob(os.path.join(RULES_DIR, "*.yml"))
        + glob.glob(os.path.join(RULES_DIR, "*.yaml"))
    )

    if not files:
        print(f"No Sigma rules found in {RULES_DIR}")
        return

    for filepath in sorted(files):

        try:
            rule = parse_sigma_rule(filepath)
            rules.append(rule)

            print(
                f"Converted: {os.path.basename(filepath)}"
            )

        except Exception as e:

            print(
                f"Failed to parse "
                f"{os.path.basename(filepath)}: {e}"
            )

    vm_config = {
        "groups": [
            {
                "name": "sigma_rules_group",
                # Explicitly set type to vlogs for native VictoriaLogs parsing
                "type": "vlogs",
                # Evaluate every 10 seconds.
                "interval": "10s",
                "rules": rules
            }
        ]
    }

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        yaml.dump(
            vm_config,
            f,
            default_flow_style=False,
            sort_keys=False
        )

    print(
        f"\nSuccessfully generated "
        f"{len(rules)} VMAlert rules at "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    generate_vmalert_config()