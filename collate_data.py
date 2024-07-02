import json

findings = {}
violations = {}
with open("./findings-data-inconsistent.json", "r") as file:
    findings = json.load(file)
with open("./violation-data-inconsistent.json", "r") as file:
    violations = json.load(file)


def collate_scm(findings, violations, provider):
    github_findings = findings.get("umg").get(provider)
    github_violations = violations.get("umg").get(provider)

    github_data = []
    for finding_topic in github_findings:
        findings = github_findings.get(finding_topic)
        github_data = github_data + findings
    for violation_topic in github_violations:
        violations = github_violations.get(violation_topic)
        github_data = github_data + violations

    with open(f"./only-{provider}.json", "w") as file:
        json.dump(github_data, file, indent=4)

    return github_data


github_data = collate_scm(findings, violations, "GITHUB")
gitlab_data = collate_scm(findings, violations, "GITLAB")

github_rules_not_found = []
for item in github_data:
    github_rule_name = item.get("originalRuleId")

    found_rule = False
    for gl_item in gitlab_data:
        if gl_item.get("originalRuleId") == github_rule_name:
            found_rule = True
            break

    if found_rule == False:
        github_rules_not_found.append(item)

with open("./github-rules-not-found.json", "w") as file:
    json.dump(github_rules_not_found, file, indent=4)
