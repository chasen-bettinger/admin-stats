import csv
import json
import boost
import csv_structure

# header_row = csv_structure.build_header_row(["account_name"])
# header_row = header_row + [
#     "scans_run",
#     "scans_failed",
#     "most_recent_successful_scan",
#     # "scan_failures",
# ]
# final_csv = [header_row]

# ---

# accounts_to_look_at = ["chasen-bettinger"]
# accounts_to_look_at = [
#     "hubintl",
#     "momsmeals",
#     "umg",
#     "dwp",
#     "truu",
#     "jamcity",
#     "mattel",
# ]
accounts = boost.get_accounts()
ledger = {}
for account in accounts:
    account_name = account.get("name")
    # if account_name not in accounts_to_look_at:
    #     continue

    account_token = boost.get_token(account.get("accountId"), account.get("orgId"))
    token_to_use = f"Bearer {account_token}"
    account_name_original = account_name
    account_name = account_name.replace("-", "_")

    # ---
    asset_ids = boost.get_asset_ids(account_name, token_to_use)
    assets_by_name = {}
    for asset in asset_ids:
        asset_node = asset.get("node")
        asset_name = asset_node.get("name")
        assets_by_name[asset_name] = asset_node

    provisioned_analyzers = ["scanner"]
    posture_filters = boost.get_security_posture_filters(
        options={
            "provisioned_analyzers": provisioned_analyzers,
            "token": token_to_use,
            "org": account_name,
        }
    )
    collections = posture_filters.get("collection")
    targets = {}
    for collection in collections:
        collection_name = collection.get("display").get("name")

        asset_details = assets_by_name[collection_name]

        # if absent, will incur a 'providerId' missing
        # error
        # possible_improvement: consider omitting isOrphan from
        # network request
        if asset_details.get("isOrphan"):
            continue

        collection_id = asset_details.get("id")
        collection_provider = asset_details.get("provider")

        affected_resources = boost.get_resources(
            options={
                "provider_id": collection_provider,
                "collection_id": collection_id,
                "provisioned_analyzers": provisioned_analyzers,
                "token": token_to_use,
                "org": account_name,
            }
        )

        for ar in affected_resources:
            resource_name = ar.get("node").get("name")

            if targets.get(collection_name) == None:
                targets[collection_name] = []

            targets[collection_name].append(resource_name)

    ledger[account_name] = targets


with open("./ledger.json", "w") as file:
    json.dump(ledger, file, indent=4)


# with open("./060524-account-overview.csv", "w", newline="") as file:
#     writer = csv.writer(file)
#     writer.writerows(final_csv)
