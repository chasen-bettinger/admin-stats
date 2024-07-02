import json
import boost


accounts_to_look_at = ["umg"]
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
    if account_name not in accounts_to_look_at:
        continue

    account_token = boost.get_token(account.get("accountId"), account.get("orgId"))
    token_to_use = f"Bearer {account_token}"
    account_name_original = account_name
    account_name = account_name.replace("-", "_")

    # ---
    group_findings = boost.get_group_findings(
        options={
            "is_violation": False,
            "viewer_asset_ids": [
                "97061027-ef20-54cf-a22d-4f36e0323fd3",
                "1b142503-6f05-5f03-941d-d7be4be1d237",
            ],
            "org": account_name,
            "token": token_to_use,
        }
    )
    rule_id_count = {}
    for record in group_findings:
        n = record.get("node")
        scm_provider = n.get("asset").get("scmProvider")

        original_rule_id = n.get("ruleName")

        if rule_id_count.get(scm_provider) == None:
            rule_id_count[scm_provider] = {}

        t = rule_id_count[scm_provider]
        if t.get(original_rule_id) == None:
            t[original_rule_id] = []

        t[original_rule_id].append(n)

    ledger[account_name] = rule_id_count


with open("./findings-data-inconsistent.json", "w") as file:
    json.dump(ledger, file, indent=4)
