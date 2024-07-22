import network
from urls import urls
import queries
from queries import (
    analytics_summary,
    analytics_scan_metrics,
    analytics_scans,
    get_accounts_query,
)
import mutations


def get_most_recent_successful_scan(options):
    org = options.get("org")
    token = options.get("token")
    from_date = options.get("from_date")
    to_date = options.get("to_date")
    most_recent_successful_scan_options = {
        "url": urls["analysis_history"],
        "tl_property": "analyses",
        "query": analytics_scans,
        "params": {
            "first": 1,
            "assets": [],
            "assetTypes": [],
            "analyzers": [
                "boostsecurityio/semgrep-pro",
                "boostsecurityio/osv-scanner",
                "boostsecurityio/trivy-fs",
                "boostsecurityio/snyk-test",
                "boostsecurityio/checkov-tf-plan",
                "boostsecurityio/trivy-image",
                "boostsecurityio/gitleaks-full",
                "boostsecurityio/bundler-audit",
                "boostsecurityio/semgrep",
                "boostsecurityio/supply-chain-inventory",
                "boostsecurityio/nancy",
                "boostsecurityio/composition",
                "boostsecurityio/safety",
                "boostsecurityio/npm-audit",
                "boostsecurityio/brakeman",
                "boostsecurityio/boost-sca",
                "boostsecurityio/codeql",
                "boostsecurityio/gosec",
                "boostsecurityio/trivy-sbom-image",
                "boostsecurityio/checkov",
                "scanner",
                "boostsecurityio/gitleaks",
                "boostsecurityio/scanner",
                "boostsecurityio/trivy-sbom",
            ],
            "statuses": ["SUCCESS"],
            "assetIds": [],
            "fromDate": from_date,
            "toDate": to_date,
            "page": 1,
        },
        "token": token,
        "meta": {"org": org, "request": "most_recent_successful_scan"},
        "label": f"{org}_most_recent_successful_scan",
    }

    most_recent_successful_result = network.check_cache(
        most_recent_successful_scan_options
    )
    return most_recent_successful_result["analyses"]


def get_analytics_summary(options):
    org = options.get("org")
    token = options.get("token")
    from_date = options.get("from_date")
    to_date = options.get("to_date")
    analytics_options = {
        "url": urls["analytics"],
        "query": analytics_summary,
        "params": {
            "from_day": from_date,
            "to_day": to_date,
            "bucket_size": "DAY",
            "max_rules": 5,
            "policyIds": [],
            "page": 1,
        },
        "token": token,
        "meta": {"org": org, "request": "analytics_summary"},
        "label": f"{org}_analytics_summary",
    }

    result = network.check_cache(analytics_options)
    return result["insights"]["summary"]


def get_scan_metrics(options):
    org = options.get("org")
    token = options.get("token")
    from_date = options.get("from_date")
    to_date = options.get("to_date")
    scan_metric_options = {
        "url": urls["analysis_history"],
        "query": analytics_scan_metrics,
        "params": {
            "fromDate": from_date,
            "toDate": to_date,
            "policyIds": [],
            "page": 1,
        },
        "token": token,
        "meta": {"org": org, "request": "analysis_scan_metrics"},
        "label": f"{org}_analysis_scan_metrics",
    }

    scan_metrics_result = network.check_cache(scan_metric_options)
    return scan_metrics_result["scanMetrics"]


def get_scan_history(options):
    resp = []

    def process_output(response):
        nonlocal resp
        edges = response.get("analyses").get("edges")
        resp = resp + edges

    org = options.get("org")
    token = options.get("token", None)
    statuses = options.get("statuses", ["ERROR", "BROKEN_INSTALLATION", "TIMEOUT"])
    # TODO: better defaults
    from_date = options.get("from_date", "2024-05-22")
    to_date = options.get("to_date", "2024-06-05")
    asset_types = options.get(
        "asset_types", ["SCM_ORGANIZATION", "SCM_REPOSITORY_CODE_CHANGE"]
    )
    scan_history_options = {
        "url": urls["analysis_history"],
        "post_execution": process_output,
        "page_info_pointer": ["analyses"],
        "query": analytics_scans,
        "params": {
            "first": 100,
            "assets": [],
            "assetTypes": asset_types,
            "analyzers": [],
            "statuses": statuses,
            "assetIds": [],
            "fromDate": from_date,
            "toDate": to_date,
            "page": 1,
        },
        "token": token,
        "meta": {"org": org, "request": "analysis_scan_history"},
        "label": f"{org}_analysis_scan_history",
    }

    network.paginate(scan_history_options)
    return resp


def get_accounts():
    network_options = {
        "url": urls["account_admin"],
        "params": {
            "page": 1,
        },
        "query": get_accounts_query,
        "label": "get_accounts",
    }
    resp = network.check_cache(network_options)
    return resp["accounts"]


def get_token(account_id, organization_id):
    network_options = {
        "url": urls["account_admin"],
        "params": {
            "accountId": account_id,
            "organizationId": organization_id,
            "features": [],
        },
        "query": mutations.create_token,
    }
    resp = network.request_gql(network_options)
    return resp["createActAsToken"]["token"]

    # "assetIds": ["b2cd2f27-4ce7-51b1-a297-d9e0cd0e7069"],


def apply_provision_plan(options):
    network_options = {
        "url": urls["asset_management"],
        "params": {
            "assetSelection": [
                {
                    "selectionType": "ASSET",
                    "assetType": "RESOURCE",
                    "assetIds": options.get("asset_ids"),
                }
            ],
            "scanners": options.get("scanners"),
        },
        "query": mutations.apply_provision_plan,
        "label": "apply_provision_plan",
    }

    network.request_gql(network_options)
    return True


def get_assets(collectionId):

    params = {"first": 100, "page": 1, "filters": {"search": ""}}
    label = "get_assets"

    if collectionId != None:
        params.update({"collectionId": collectionId})
        label = label + f"_{collectionId}"

    network_options = {
        "url": urls["asset_inventory"],
        "tl_property": "assetManagement",
        "sl_property": "collections",
        "params": params,
        "query": queries.get_collections,
        "label": label,
    }

    resp = network.check_cache(network_options)
    return resp["assetManagement"]["collections"]


def get_asset_ids(org, token):
    request = "get_asset_ids"
    resp = []

    def process_output(response):
        nonlocal resp
        edges = response.get("assetManagement").get("collections").get("edges")
        resp = resp + edges

    params = {"first": 100, "page": 1, "filters": {"search": ""}}
    label = f"{org}_{request}"

    network_options = {
        "url": urls["asset_inventory"],
        "page_info_pointer": ["assetManagement", "collections"],
        "post_execution": process_output,
        "params": params,
        "query": queries.get_collections,
        "label": label,
        "meta": {"org": org, "request": request},
    }

    if token != None:
        network_options["token"] = token

    network.paginate(network_options)
    return resp


def get_repository_ids(collection_id):

    params = {"first": 100, "page": 1, "filters": {"search": ""}}
    label = "get_repository_ids"

    if collection_id != None:
        params.update({"collectionId": collection_id})
        safe_collection_id = collection_id.replace("-", "_")
        label = label + f"_{safe_collection_id}"

    network_options = {
        "url": urls["asset_inventory"],
        "tl_property": "collection",
        "sl_property": "resources",
        "params": params,
        "query": queries.get_repository_ids,
        "label": label,
    }

    resp = network.check_cache(network_options)
    return resp["collection"]["resources"]


def get_resources(options):
    request = "get_resources"
    org = options.get("org")
    resp = []

    def process_output(response):
        nonlocal resp
        edges = response.get("provider").get("collection").get("resources").get("edges")
        resp = resp + edges

    provider_id = options.get("provider_id")
    collection_id = options.get("collection_id")
    provisioned_analyzers = options.get("provisioned_analyzers", [])
    resource_attributes = options.get("resource_attributes", [])
    no_cache = options.get("no_cache", False)

    params = {
        "providerId": provider_id,
        "collectionId": collection_id,
        "filters": {
            "resourceProvisioningStatuses": [],
            "collections": [],
            "missingCoverages": [],
            "policy": [],
            "policyType": [],
            "resourceAttributes": resource_attributes,
            "provisionedAnalyzers": provisioned_analyzers,
            "search": "",
        },
        "first": 100,
        "page": 1,
    }
    label = f"{org}_{request}"

    if collection_id != None:
        safe_collection_id = collection_id.replace("-", "_")
        label = label + f"_{safe_collection_id}"

    network_options = {
        "url": urls["asset_management"],
        "post_execution": process_output,
        "page_info_pointer": ["provider", "collection", "resources"],
        "params": params,
        "query": queries.get_resources,
        "label": label,
        "meta": {"org": org, "request": request},
        "page": 1,
        "no_cache": no_cache,
    }

    if options.get("token") != None:
        network_options["token"] = options.get("token")

    network.paginate(network_options)
    return resp


def get_security_posture_filters(options):
    request = "get_security_posture_filters"
    provisioned_analyzers = options.get("provisioned_analyzers", [])
    resource_attributes = options.get("resource_attributes", [])

    params = {
        "filters": {
            "resourceProvisioningStatuses": [],
            "collections": [],
            "missingCoverages": [],
            "policy": [],
            "policyType": [],
            "resourceAttributes": resource_attributes,
            "provisionedAnalyzers": provisioned_analyzers,
            "search": "",
        },
        "page": 1,
    }
    org = options.get("org")
    label = f"{org}_{request}"

    network_options = {
        "url": urls["asset_management"],
        "params": params,
        "query": queries.get_security_posture_filters,
        "label": label,
        "meta": {"org": org, "request": request},
    }

    if options.get("token") != None:
        network_options["token"] = options.get("token")

    if options.get("no_cache") == True:
        resp = network.request_gql(network_options)
    else:
        resp = network.check_cache(network_options)

    return resp.get("securityPosture").get("filters")


def get_group_findings(options):
    request = "get_group_findings"
    org = options.get("org")
    resp = []

    def process_output(response):
        nonlocal resp
        edges = response.get("groups").get("edges")
        resp = resp + edges

    params = {
        "filters": {
            "detailsDependencyScopes": [],
            "ruleNames": [],
            "isViolation": options.get("is_violation", True),
            "securityCategories": [],
            "severities": [],
            "confidences": [],
            "viewerAssetIds": options.get("viewer_asset_ids", []),
            "processingStatus": [],
            "suppressionTag": [],
            "ruleGroups": options.get("rule_groups", []),
            "scannerIds": options.get("scanner_ids", []),
            "vulnerabilityIdentifiers": [],
            "repositoryAttributes": [],
            "policyId": [],
        },
        "first": 100,
        "orderBy": [],
        "page": 1,
    }
    label = f"{org}_{request}"

    network_options = {
        "url": urls["findings_view"],
        "post_execution": process_output,
        "page_info_pointer": ["groups"],
        "params": params,
        "query": queries.get_group_findings,
        "label": label,
        "meta": {"org": org, "request": request},
        "page": 1,
    }

    if options.get("token") != None:
        network_options["token"] = options.get("token")

    network.paginate(network_options)
    return resp


def get_security_posture_filter_attributes(options):
    request = "get_security_posture_filter_attributes"

    params = {
        "filters": {
            "resourceProvisioningStatuses": [],
            "collections": [],
            "missingCoverages": [],
            "policy": [],
            "policyType": [],
            "resourceAttributes": [],
            "provisionedAnalyzers": [],
            "search": "",
        },
        "page": 1,
    }
    org = options.get("org")
    label = f"{org}_{request}"

    network_options = {
        "url": urls["asset_management"],
        "params": params,
        "query": queries.get_security_posture_attributes,
        "label": label,
        "meta": {"org": org, "request": request},
    }

    if options.get("token") != None:
        network_options["token"] = options.get("token")

    resp = network.check_cache(network_options)
    return resp.get("securityPosture").get("filters")
