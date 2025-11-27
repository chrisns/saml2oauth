import requests

from shim_utils import jprint

# Timeout for SCIM API requests in seconds
SCIM_TIMEOUT = 30


def escape_scim_filter_value(value: str) -> str:
    """
    SECURITY: Escape special characters in SCIM filter values to prevent filter injection.
    SCIM filter values need backslash and double-quote escaped.
    """
    if not value:
        return value
    return value.replace("\\", "\\\\").replace('"', '\\"')


def push_user_info_to_scim(base_url, access_token, claims):
    base_url = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    user_info = build_user_info(claims)
    email = user_info.get("emails", [{}])[0].get("value")
    if not email:
        raise ValueError("SCIM user must have an email")

    # Look up existing user (escape email for SCIM filter injection prevention)
    search_url = f'{base_url}/Users?filter=emails.value eq "{escape_scim_filter_value(email)}"'
    search = requests.get(search_url, headers=headers, timeout=SCIM_TIMEOUT)

    if search.status_code != 200:
        raise RuntimeError(f"SCIM search failed: {search.status_code} {search.text}")

    resources = search.json().get("Resources", [])
    jprint("SCIM search results:", resources)

    resp = None
    user_id = None
    if resources:
        # User exists -> PUT full replace
        user_id = resources[0]["id"]
        user_info["id"] = user_id
        put_url = f"{base_url}/Users/{user_id}"
        resp = requests.put(put_url, headers=headers, json=user_info, timeout=SCIM_TIMEOUT)
    else:
        # User not found -> POST create
        resp = requests.post(f"{base_url}/Users", headers=headers, json=user_info, timeout=SCIM_TIMEOUT)
        user_id = resp.json().get("id")

    groups = claims.get("groups", [])
    if groups:
        sync_groups_for_user(user_id, groups, base_url, headers)

    return resp


def find_scim_group(base_url, group_name, headers):
    base_url = base_url.rstrip("/")
    # SCIM filter query by displayName (escape for SCIM filter injection prevention)
    url = f'{base_url}/Groups?filter=displayName eq "{escape_scim_filter_value(group_name)}"'
    resp = requests.get(url, headers=headers, timeout=SCIM_TIMEOUT)

    if resp.status_code != 200:
        raise RuntimeError(f"SCIM group search failed: {resp.status_code} {resp.text}")

    resources = resp.json().get("Resources", [])
    return resources[0] if resources else None


def create_scim_group(base_url, group_name, headers):
    base_url = base_url.rstrip("/")
    body = {"displayName": group_name, "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]}
    resp = requests.post(f"{base_url}/Groups", headers=headers, json=body, timeout=SCIM_TIMEOUT)

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"SCIM group create failed: {resp.status_code} {resp.text}")

    return resp.json()


def sync_groups_for_user(user_id, user_groups, scim_base_url, headers):
    for grp in user_groups:
        # 1. Find or create SCIM group
        g = find_scim_group(scim_base_url, grp, headers)
        if not g:
            g = create_scim_group(scim_base_url, grp, headers)

        group_id = g["id"]

        # 2. Add user to group
        patch_body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}],
        }
        requests.patch(f"{scim_base_url}/Groups/{group_id}", headers=headers, json=patch_body, timeout=SCIM_TIMEOUT)


def build_user_info(claims):
    user_info = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": claims.get("email"),
        "externalId": claims.get("sub"),
        "active": True,
        "emails": [{"value": claims.get("email"), "type": "work"}],
    }

    displayName = claims.get("display_name", None)
    if displayName:
        user_info["displayName"] = displayName

    given_name = claims.get("given_name", None)
    if given_name:
        user_info["name"] = {}
        user_info["name"]["givenName"] = given_name

    family_name = claims.get("family_name", None)
    if family_name:
        if not user_info["name"]:
            user_info["name"] = {}
        user_info["name"]["familyName"] = family_name

    return user_info
