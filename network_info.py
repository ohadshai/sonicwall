from strenum import StrEnum
from enum import auto

PLACEHOLDER = "{}"


class Mode(StrEnum):
    blockexternal = auto()
    blockinternal = auto()
    unblockexternal = auto()
    unblockinternal = auto()


class Zone(StrEnum):
    LAN = auto()
    WAN = auto()


MODE_INFO = {
    Mode.blockexternal.value:
    {
        "policy_name": "Cynet Block External Destination IP",
        "address_group_name": "Cynet Destination Block",
        "address_object_name": f"cynet-{Mode.blockexternal.value}-{PLACEHOLDER}",
        "object_zone": Zone.WAN.value,
        "policy_from_zone": Zone.LAN.value,
        "policy_to_zone": Zone.WAN.value,
        "policy_source_address": {'any': True},
        "policy_destination_address": {"group": "Cynet Destination Block"}
    },
    Mode.blockinternal.value:
    {
        "policy_name": "Cynet Block Internal Source IP",
        "address_group_name": "Cynet Source Block",
        "address_object_name": f"cynet-{Mode.blockinternal.value}-{PLACEHOLDER}",
        "object_zone": Zone.LAN.value,
        "policy_from_zone": Zone.LAN.value,
        "policy_to_zone": Zone.LAN.value,
        "policy_source_address": {"group": "Cynet Source Block"},
        "policy_destination_address": {'any': True},
    },
}

SECURITY_POLICY_TEMPLATE = {
    "ipv4": {
        "name": None,
        "uuid": None,
        "enable": True,
        "priority": {
            "manual": 1
        },
        "from": None,
        "to": None,
        "source": {
            "address": {}
        },
        "destination": {
            "address": {}
        },
        "service": {
            "any": True
        },
        "users": {
            "all": True
        },
        "match_operation": "or",
        "application": {
            "any": True
        },
        "and_all_matched_applications": False,
        "web_category": {
            "any": True
        },
        "url_list": {
            "any": True
        },
        "custom_match": {
            "any": True
        },
        "country": {
            "any": True
        },
        "schedule": {
            "always_on": True
        },
        "action": "deny",
        "action_profile": "Default Profile",
    }
}

ADDRESS_GROUP_TEMPLATE = {
    "ipv4": {
        "name": None,
        "address_object": {
            "ipv4": [
                {
                    "name": None
                }
            ]
        }
    }
}

ADDRESS_OBJECT_TEMPLATE = {
    "ipv4": {
        "name": None,
        "zone": None,
        "host": {
            "ip": None
        }
    }
}
