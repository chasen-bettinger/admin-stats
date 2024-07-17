import boost
import json

org_name = "boost"
asset_ids = boost.get_asset_ids(org_name, None)
assets_by_name = {}
for asset in asset_ids:
    asset_node = asset.get("node")
    asset_name = asset_node.get("name")
    assets_by_name[asset_name] = asset_node


resource_attributes = ["internal"]

posture_filters = boost.get_security_posture_filters(
    options={
        "org": org_name,
        "resource_attributes": resource_attributes,
        "no_cache": True,
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

    print("finding for collection... ", collection_name)
    affected_resources = boost.get_resources(
        options={
            "provider_id": collection_provider,
            "collection_id": collection_id,
            "resource_attributes": resource_attributes,
            "org": org_name,
            "no_cache": True,
        }
    )

    for ar in affected_resources:
        resource_name = ar.get("node").get("name")

        if targets.get(collection_name) == None:
            targets[collection_name] = []

        targets[collection_name].append(resource_name)

attribute_str = "_".join(resource_attributes)
file_name = f"./repositories_with_{attribute_str}.json"

with open(file_name, "w") as file:
    file.write(json.dumps(targets, indent=4))
