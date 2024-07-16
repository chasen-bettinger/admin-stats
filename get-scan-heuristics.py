import csv
import boost
import csv_structure


# ---
def flatten_dict(d, parent_key="", sep="_"):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


flatten_parent_key = "scan_history_node"


def get_header_row(node):
    header_row = []
    n = flatten_dict(node, parent_key=flatten_parent_key)
    for key in n:
        header_row.append(key)

    return header_row


time_ledger = {"main": {}, "pr": {}}
# accounts_to_look_at = ["chasen-bettinger"]
accounts_to_look_at = [
    "demandbase",
]
accounts = boost.get_accounts()
for account in accounts:
    account_name = account.get("name")
    if account_name not in accounts_to_look_at:
        continue

    account_token = boost.get_token(account.get("accountId"), account.get("orgId"))
    token_to_use = f"Bearer {account_token}"
    account_name_original = account_name
    account_name = account_name.replace("-", "_")

    # ---
    scan_history_options = {
        "org": account_name,
        "token": token_to_use,
        "from_date": "2024-06-17",
        "to_date": None,
        "asset_types": ["SCM_REPOSITORY_CODE", "SCM_REPOSITORY_CODE_CHANGE"],
    }
    scan_history = boost.get_scan_history(scan_history_options)

    header_row = get_header_row(scan_history[2].get("node"))

    final_csv = [header_row]

    for sh in scan_history:
        n = sh.get("node")
        n = flatten_dict(n, parent_key=flatten_parent_key)
        current_node = []
        for key in header_row:
            v = n.get(key, "cannot_parse")

            if key == "scan_history_node_resource_resourceType":
                if v == "SCM_REPOSITORY_CODE":
                    v = "default"

                else:
                    v = "pr"

            current_node.append(v)

        final_csv.append(current_node)

with open("./now-scan-history-output.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerows(final_csv)
