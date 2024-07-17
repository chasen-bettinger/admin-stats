import boost
import json

attributes_from_network = boost.get_security_posture_filter_attributes({})
resourceAttributes = attributes_from_network.get("resourceAttribute", [])
attributes = []
for a in resourceAttributes:
    v = a.get("value")
    attributes.append(v)

with open("attributes.json", "w") as f:
    f.write(json.dumps(attributes, indent=4))
