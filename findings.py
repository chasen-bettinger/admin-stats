import boost
import json

gf = boost.get_group_findings(options={"org": "boost"})

with open("./gf.json", "w") as file:
    json.dump(gf, file, indent=4)


data = []
with open("./gf.json", "r") as file:
    data = json.load(file)

# print(len(data))
ledger = {}
for record in data:
    n = record.get("node")
    original_rule_id = n.get("originalRuleId")
    if originial
#     node_scanners = n.get("scanners")
#     no_gitleaks = True
#     for s in node_scanners:
#         if s.get("scannerId") == "boostsecurityio/gitleaks":
#             no_gitleaks = False
#             break

#     if no_gitleaks == True:
#         continue

#     original_rule_id = n.get("originalRuleId")

#     if rule_id_count.get(original_rule_id) == None:
#         rule_id_count[original_rule_id] = 0

#     rule_id_count[original_rule_id] = rule_id_count[original_rule_id] + 1

with open("./ledger-ogruleid.json", "w") as file:
    json.dump(ledger, file)
