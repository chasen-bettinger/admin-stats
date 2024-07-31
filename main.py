import csv
import boost
import csv_structure
from datetime import datetime, timedelta

header_row = csv_structure.build_header_row(["account_name"])
header_row = header_row + [
    "scans_run",
    "scans_failed",
    "most_recent_successful_scan",
    # "scan_failures",
]
final_csv = [header_row]

# ---

# TODO: create reusable options utility

current_date = datetime.now()
four_weeks_ago = current_date - timedelta(weeks=4)
formatted_date = current_date.strftime("%Y-%m-%d")
four_weeks_ago_formatted_date = four_weeks_ago.strftime("%Y-%m-%d")

accounts_to_look_at = ["mattel", "audubon"]
"""
accounts_to_look_at = [
    "hubintl",
    "momsmeals",
    "umg",
    "dwp",
    "truu",
    "jamcity",
    "mattel",
]
"""


accounts = boost.get_accounts()
for account in accounts:
    account_name = account.get("name")
    if account_name not in accounts_to_look_at:
        continue

    account_token = boost.get_token(account.get("accountId"), account.get("orgId"))
    token_to_use = f"Bearer {account_token}"
    account_name_original = account_name
    account_name = account_name.replace("-", "_")

    def get_options(options=None):
        base_options = {
            "org": account_name,
            "token": token_to_use,
            "from_date": four_weeks_ago_formatted_date,
            "to_date": formatted_date,
        }

        if options != None:
            base_options.update(options)

        return base_options

    # ---
    analytics_summary = boost.get_analytics_summary(get_options())
    scan_metrics = boost.get_scan_metrics(get_options())
    scan_history_options = {
        "statuses": [],
    }
    scan_history = boost.get_scan_history(get_options(scan_history_options))
    most_recent_successful_scan = boost.get_most_recent_successful_scan(get_options())

    # ---
    account_row = csv_structure.build_account_row(
        [account_name_original],
        analytics_summary,
    )

    most_recent_successful_node = {}
    successful_scan_edges = most_recent_successful_scan.get("edges", [])
    if len(successful_scan_edges) > 0:
        most_recent_successful_node = successful_scan_edges[0].get("node")

    most_recent_successful_timestamp = most_recent_successful_node.get(
        "timestamp", "N/A"
    )
    most_recent_successful_scanner = most_recent_successful_node.get(
        "analyzer", {}
    ).get("analyzerName", "N/A")
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


for index, v in enumerate(final_csv):
    if index == 0:
        continue

    for jndex, w in enumerate(v):
        header = final_csv[0][jndex]
        output = f"{header}: {w}"
        print(output)


with open(f"./{formatted_date}-account-overview.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerows(final_csv)
