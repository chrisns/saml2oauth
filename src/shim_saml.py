import base64
import json
import re
import secrets
from datetime import datetime, timedelta
from html import escape as html_escape

import boto3
from lxml import etree
from signxml import XMLSigner, methods

from shim_utils import jprint

NSMAP = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def fetch_cert_and_key(secret_name: str, host: str):
    """
    Fetch IdP signing keypair from Secrets Manager.
    The keypair is created by Terraform, not at runtime.
    """
    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=secret_name)
    data = json.loads(resp["SecretString"])
    return data["private_key_pem"], data["cert_pem"]


def get_saml_metadata(login_url, logout_url, idp_entity_id, NAMEID_FORMAT, secret_name: str, host: str):
    _, IDP_METADATA_PEM = fetch_cert_and_key(secret_name, host)

    # Strip PEM headers/footers and newlines for embedding into <ds:X509Certificate>
    cert_b64 = "".join(IDP_METADATA_PEM.strip().splitlines())
    cert_b64 = cert_b64.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()

    xml = f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{idp_entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="{NSMAP["saml2p"]}">
    <md:NameIDFormat>{NAMEID_FORMAT}</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{login_url}" />
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{logout_url}" />
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    # <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{login_url}" />
    # <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{logout_url}" />

    return xml


def build_saml_response(
    idp_cert, idp_key, SP_ACS_URL, SP_ENTITY_ID, NAMEID_FORMAT, claims, issuer, saml_request_b64=None
):
    # Extremely minimal unsigned assertion for MVP
    now = datetime.utcnow()
    expiry = now + timedelta(minutes=5)

    email = claims.get("email")
    claims.get("sub")

    in_response_to_attr = ""
    if saml_request_b64:
        saml_request_str = base64.b64decode(saml_request_b64).decode("utf-8")
        if "ID=" in saml_request_str:
            saml_request_id = re.search(r'\sID="([^"]+)"', saml_request_str).group(1)
            jprint("Discovered SAML request ID:", saml_request_id)
            in_response_to_attr = f'InResponseTo="{saml_request_id}"' if saml_request_id else ""

    attrs_xml = ""

    def attr(name, value):
        """Build a SAML attribute element with escaped value."""
        escaped = html_escape(value)
        return (
            f'<saml2:Attribute Name="{name}"><saml2:AttributeValue>{escaped}</saml2:AttributeValue></saml2:Attribute>'
        )

    # SECURITY: Escape all claim values to prevent XML injection
    if email:
        attrs_xml += attr("email", email)
        attrs_xml += attr("mail", email)
        attrs_xml += attr("https://aws.amazon.com/SAML/Attributes/RoleSessionName", email)

    name = claims.get("display_name")
    if name:
        attrs_xml += attr("name", name)
        attrs_xml += attr("displayName", name)

    given_name = claims.get("given_name")
    if given_name:
        attrs_xml += attr("givenName", given_name)

    family_name = claims.get("family_name")
    if family_name:
        attrs_xml += attr("surname", family_name)

    groups = claims.get("groups") or []
    if groups:
        group_values = "".join(f"<saml2:AttributeValue>{html_escape(g)}</saml2:AttributeValue>" for g in groups)
        attrs_xml += f'<saml2:Attribute Name="groups">{group_values}</saml2:Attribute>'

    # SECURITY: Use cryptographically random IDs instead of predictable timestamps
    response_id = f"_shim_{secrets.token_urlsafe(16)}"
    assertion_id = f"_assert_{secrets.token_urlsafe(16)}"

    root_assertion_xml = f"""<saml2p:Response
    xmlns:saml2p="{NSMAP["saml2p"]}"
    xmlns:saml2="{NSMAP["saml2"]}"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    Version="2.0">
    <saml2:Assertion xmlns:saml2="{NSMAP["saml2"]}" Version="2.0" ID="{assertion_id}" IssueInstant="{now.isoformat()}Z">
        <saml2:Issuer>{issuer}</saml2:Issuer>
        <ds:Signature Id="placeholder"></ds:Signature>
        <saml2:Subject>
            <saml2:NameID Format="{NAMEID_FORMAT}">{html_escape(email) if email else ""}</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData {in_response_to_attr}
                    NotOnOrAfter="{expiry.isoformat()}Z"
                    Recipient="{SP_ACS_URL}" />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="{now.isoformat()}Z" NotOnOrAfter="{expiry.isoformat()}Z">
            <saml2:AudienceRestriction>
                <saml2:Audience>{SP_ENTITY_ID}</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="{now.isoformat()}Z" SessionIndex="{assertion_id}">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
        {attrs_xml}
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>"""

    # Parse XML
    root = etree.fromstring(root_assertion_xml.encode("utf-8"))
    assertion = root.find(".//saml2:Assertion", namespaces=NSMAP)

    # Sign the Assertion (enveloped signature, RSA-SHA256)
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )

    signed_assertion = signer.sign(
        assertion,
        key=idp_key,
        cert=idp_cert,
        reference_uri=f"#{assertion_id}",
        id_attribute="ID",
    )

    signed_xml = etree.tostring(signed_assertion, xml_declaration=False, encoding="utf-8").decode("utf-8")

    response_xml = f"""<saml2p:Response
    xmlns:saml2p="{NSMAP["saml2p"]}"
    xmlns:saml2="{NSMAP["saml2"]}"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    Version="2.0"
    ID="{response_id}"
    IssueInstant="{now.isoformat()}Z"
    Destination="{SP_ACS_URL}" {in_response_to_attr}>
  <saml2:Issuer>{issuer}</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  {signed_xml}
</saml2p:Response>"""

    return_b64 = base64.b64encode(response_xml.encode("utf-8")).decode("ascii")
    return return_b64
