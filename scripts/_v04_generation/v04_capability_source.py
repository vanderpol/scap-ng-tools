"""Version-neutral pinned OVAL XSD field extraction for native generation.

These reviewed helpers preserve the existing datatype interpretation. They do
not construct any SCAP-NG grammar or import a historical schema generator.
"""
XSD = "{http://www.w3.org/2001/XMLSchema}"

def direct_global(root, kind, name):
    for child in root:
        if child.tag == XSD + kind and child.get("name") == name:
            return child
    raise KeyError(f"missing global {kind} {name!r}")

def restriction_values(node):
    values = []
    for child in node.iter():
        if child.tag == XSD + "enumeration" and child.get("value") is not None:
            values.append(child.get("value"))
    return values

def source_datatypes(element):
    typed = element.get("type") or ""
    suffix_map = {
        "EntityStateStringType": ["string"],
        "EntityStateIntType": ["integer"],
        "EntityStateBoolType": ["boolean"],
        "EntityStateFloatType": ["float"],
        "EntityStateVersionType": ["version"],
        "EntityStateIPAddressStringType": ["string"],
        "EntityItemStringType": ["string"],
        "EntityItemIntType": ["integer"],
        "EntityItemBoolType": ["boolean"],
        "EntityItemFloatType": ["float"],
        "EntityItemVersionType": ["version"],
        "EntityItemIPAddressStringType": ["string"],
        "EntityItemRecordType": ["record"],
        "EntityObjectStringType": ["string"],
        "EntityObjectIntType": ["integer"],
        "EntityObjectBoolType": ["boolean"],
        "EntityObjectFloatType": ["float"],
        "EntityObjectVersionType": ["version"],
        "EntityObjectIPAddressStringType": ["string"],
    }
    short = typed.split(":")[-1]
    if short in suffix_map:
        return suffix_map[short]

    # Some OVAL fields use an inline restriction with a narrowed datatype
    # attribute. Prefer that explicit enumeration when present.
    for attr in element.iter():
        if attr.tag == XSD + "attribute" and attr.get("name") == "datatype":
            values = restriction_values(attr)
            if values:
                return [
                    {
                        "int": "integer",
                        "ipv4_address": "ipv4",
                        "ipv6_address": "ipv6",
                        "evr_string": "rpm_evr",
                        "debian_evr_string": "debian_evr",
                    }.get(value, value)
                    for value in values
                ]
            if attr.get("default"):
                return [attr.get("default")]
    return ["string"]

def immediate_payload_elements(global_element):
    """Return direct semantic elements under extension/sequence/choice payload.

    For State this returns direct State entities. For Object it discovers named
    selector entities while avoiding nested annotation/schema helper elements.
    """
    result = {}
    for node in global_element.iter():
        if node.tag != XSD + "element" or not node.get("name"):
            continue
        name = node.get("name")
        if name in result:
            continue
        result[name] = node
    return result

def infer_system_characteristics_schema(definitions_schema):
    if "-definitions-schema.xsd" not in definitions_schema:
        raise ValueError(
            f"cannot infer system-characteristics schema from {definitions_schema}"
        )
    return definitions_schema.replace(
        "-definitions-schema.xsd", "-system-characteristics-schema.xsd"
    )

def infer_item_name(source):
    if source.get("item"):
        return source["item"]
    state = source.get("state")
    if not state or not state.endswith("_state"):
        raise ValueError("source.item is required when source.state does not end in _state")
    return state[:-6] + "_item"

