import csv
import boost
import csv_structure

header_row = csv_structure.build_header_row(["account_name"])
header_row = header_row + [
    "scans_run",
    "scans_failed",
    "most_recent_successful_scan",
    # "scan_failures",
]
final_csv = [header_row]

# ---

# accounts_to_look_at = ["chasen-bettinger"]
accounts_to_look_at = [
    "hubintl",
    "momsmeals",
    "umg",
    "dwp",
    "truu",
    "jamcity",
    "mattel",
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
    analytics_summary = boost.get_analytics_summary(account_name, token_to_use)
    scan_metrics = boost.get_scan_metrics(account_name, token_to_use)
    scan_history = boost.get_scan_history(account_name, token_to_use)
    most_recent_successful_scan = boost.get_most_recent_successful_scan(
        account_name, token_to_use
    )

    # ---
    account_row = csv_structure.build_account_row(
        [account_name_original],
        analytics_summary,
    )
    most_recent_successful_node = most_recent_successful_scan.get("edges")[0].get(
        "node"
    )
    most_recent_successful_timestamp = most_recent_successful_node.get("timestamp")
    most_recent_successful_scanner = most_recent_successful_node.get("analyzer").get(
        "analyzerName"
    )
    most_recent_successful_string = (
        f"{most_recent_successful_scanner} ({most_recent_successful_timestamp})"
    )
    account_row = account_row + [
        scan_metrics["totalScans"],
        scan_metrics["totalFailedScans"],
        most_recent_successful_string,
        # csv_structure.compile_scan_failures(scan_history),
    ]
    final_csv.append(account_row)

with open("./060524-account-overview.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerows(final_csv)
