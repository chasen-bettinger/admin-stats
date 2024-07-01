import boost
import all_scanners
import pprint

scanners = ["semgrep", "trivy_sbom", "a"]
repository_targets = {"thefrenchbear": ["oregon"]}


def get_repo_ids(target):
    output = []
    assets = boost.get_asset_ids()
    for e in assets.get("edges"):
        n = e.get("node")
        org_name = n.get("name")
        org_id = n.get("id")

        if org_name not in target:
            continue

        target_values = target.get(org_name)
        repositories = boost.get_repository_ids(org_id)
        for repo in repositories.get("edges"):
            repo_node = repo.get("node")
            repo_name = repo_node.get("name")
            repo_is_orphan = repo_node.get("isOrphan")
            if repo_name in target_values and repo_is_orphan == False:
                output.append(repo_node.get("id"))

    return output


def get_scanner_definitions(scanners):

    def create_entry_definition(scanner_id):
        return {"action": "APPLY", "scannerId": scanner_id}

    scanner_definitions = []
    for scanner in scanners:
        selected_scanner = all_scanners.scanners.get(scanner)
        if selected_scanner == None:
            print(f"missing reference for {scanner}...")
            continue
        scanner_definitions.append(create_entry_definition(selected_scanner))
        print(f"added {scanner}...")

    return scanner_definitions


repo_ids = get_repo_ids(repository_targets)
provision_plan_options = {
    "asset_ids": repo_ids,
    "scanners": get_scanner_definitions(scanners),
}

print("executing the following plan..")
pp = pprint.PrettyPrinter(indent=4, width=80)
pp.pprint(provision_plan_options)
apply_response = boost.apply_provision_plan(provision_plan_options)
if apply_response == True:
    print("application successful!")
