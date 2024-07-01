import json
import boost


accounts_to_look_at = ["demandbase"]
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
            "scanner_ids": [
                "boostsecurityio/gitleaks",
                "boostsecurityio/gitleaks-full",
            ],
            "org": account_name,
            "token": token_to_use,
        }
    )
    rule_id_count = {}
    for record in group_findings:
        n = record.get("node")
        original_rule_id = n.get("originalRuleId")

        if rule_id_count.get(original_rule_id) == None:
            rule_id_count[original_rule_id] = 0

        rule_id_count[original_rule_id] = rule_id_count[original_rule_id] + 1

    ledger[account_name] = rule_id_count


with open("./gitleaks_ledger.json", "w") as file:
    json.dump(ledger, file, indent=4)
