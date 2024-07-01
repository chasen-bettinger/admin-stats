data_order = ["findings", "violations", "developerFixes", "newViolations"]


def build_header_row(list):
    for label in data_order:
        list.append(f"{label}_previous")
        list.append(f"{label}_current")
        list.append(f"{label}_change")
    return list


def build_account_row(list, data_structure):
    for label in data_order:
        metadata = get_metadata_change(data_structure, label)
        list.append(metadata["previous"])
        list.append(metadata["current"])
        list.append(metadata["change"])
    return list


def get_metadata_change(data_structure, metadata):
    previous = data_structure[metadata]["previous"]
    current = data_structure[metadata]["current"]
    change = current - previous
    if change > 0:
        change = f"+{change}"
    elif change < 0:
        change = f"({change})"

    return {"previous": previous, "current": current, "change": change}


def compile_scan_failures(scan_history):
    scan_failures = []
    for e in scan_history["edges"]:
        n = e["node"]
        scanner = n["analyzer"]["analyzerName"]
        resource = n["resource"]
        org_name = resource["organizationName"]
        repo_name = resource["repositoryName"]
        status = n["status"]
        statusName = status["statusName"]
        messages = status.get("messages")
        timestamp = n.get("timestamp")

        if messages == None:
            messages = status.get("message")

        line_item = f"{scanner} ({timestamp}) -- {org_name}/{repo_name} -- {statusName} -- {messages}"
        scan_failures.append(line_item)

    return "\n\n".join(scan_failures)
