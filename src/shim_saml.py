import json
import os
import boto3
import base64
import re
import secrets
from html import escape as html_escape

from datetime import datetime, timedelta
from lxml import etree
from signxml import XMLSigner, methods
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from shim_utils import jprint

NSMAP = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
}

def fetch_cert_and_key(secret_name: str, host: str):
    """
    Fetch an IdP signing keypair from Secrets Manager.
    If it does not exist (or is invalid), generate a new RSA key and self-signed cert,
    store them, and return (private_key_pem, cert_pem).
    """
    sm = boto3.client("secretsmanager")

    # 1. Try to read existing secret
    try:
        resp = sm.get_secret_value(SecretId=secret_name)
        if "SecretString" in resp:
            data = json.loads(resp["SecretString"])
            priv = data["private_key_pem"]
            cert = data["cert_pem"]
            return priv, cert
    except sm.exceptions.ResourceNotFoundException:
        # First run: secret not there – fall through to generate
        pass
    except Exception as e:
        # If secret is corrupt or not parseable, log and regenerate
        jprint(f"Error reading secret {secret_name}, regenerating: {e}")

    # 2. Generate new RSA keypair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    # 3. Build a self-signed cert
    now = datetime.utcnow()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Shim IdP"),
            x509.NameAttribute(NameOID.COMMON_NAME, os.getenv("IDP_COMMON_NAME", host)),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))  # ~10 years
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    # 4. Store in Secrets Manager as JSON
    secret_value = json.dumps(
        {
            "private_key_pem": private_key_pem,
            "cert_pem": cert_pem,
        }
    )

    try:
        sm.create_secret(
            Name=secret_name,
            SecretString=secret_value,
        )
    except sm.exceptions.ResourceExistsException:
        # Race / previous run created it already – just put a new version
        sm.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_value,
        )

    return private_key_pem, cert_pem


def get_saml_metadata(login_url, logout_url, idp_entity_id, NAMEID_FORMAT, secret_name: str, host: str):
    _, IDP_METADATA_PEM = fetch_cert_and_key(secret_name, host)

    # Strip PEM headers/footers and newlines for embedding into <ds:X509Certificate>
    cert_b64 = "".join(IDP_METADATA_PEM.strip().splitlines())
    cert_b64 = cert_b64.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()

    xml = f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{idp_entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="{NSMAP['saml2p']}">
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


def build_saml_response(idp_cert, idp_key, SP_ACS_URL, SP_ENTITY_ID, NAMEID_FORMAT, claims, issuer, saml_request_b64 = None):
    # Extremely minimal unsigned assertion for MVP
    now = datetime.utcnow()
    expiry = now + timedelta(minutes=5)

    email = claims.get("email")
    subject = claims.get("sub")

    in_response_to_attr = ""
    if saml_request_b64:
        saml_request_str = base64.b64decode(saml_request_b64).decode("utf-8")
        if "ID=" in saml_request_str:
            saml_request_id = re.search(r'\sID="([^"]+)"', saml_request_str).group(1)
            jprint("Discovered SAML request ID:", saml_request_id)
            in_response_to_attr = f'InResponseTo="{saml_request_id}"' if saml_request_id else ""

    attrs_xml = ""

    # SECURITY: Escape all claim values to prevent XML injection
    if email:
        email_escaped = html_escape(email)
        attrs_xml += f'<saml2:Attribute Name="email"><saml2:AttributeValue>{email_escaped}</saml2:AttributeValue></saml2:Attribute>'
        attrs_xml += f'<saml2:Attribute Name="mail"><saml2:AttributeValue>{email_escaped}</saml2:AttributeValue></saml2:Attribute>'
        attrs_xml += f'<saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml2:AttributeValue>{email_escaped}</saml2:AttributeValue></saml2:Attribute>'

    name = claims.get("display_name")
    if name:
        name_escaped = html_escape(name)
        attrs_xml += f'<saml2:Attribute Name="name"><saml2:AttributeValue>{name_escaped}</saml2:AttributeValue></saml2:Attribute>'
        attrs_xml += f'<saml2:Attribute Name="displayName"><saml2:AttributeValue>{name_escaped}</saml2:AttributeValue></saml2:Attribute>'

    given_name = claims.get("given_name")
    if given_name:
        given_name_escaped = html_escape(given_name)
        attrs_xml += f'<saml2:Attribute Name="givenName"><saml2:AttributeValue>{given_name_escaped}</saml2:AttributeValue></saml2:Attribute>'

    family_name = claims.get("family_name")
    if family_name:
        family_name_escaped = html_escape(family_name)
        attrs_xml += f'<saml2:Attribute Name="surname"><saml2:AttributeValue>{family_name_escaped}</saml2:AttributeValue></saml2:Attribute>'

    groups = claims.get("groups") or []
    if groups:
        group_values = "".join(f'<saml2:AttributeValue>{html_escape(g)}</saml2:AttributeValue>' for g in groups)
        attrs_xml += f'<saml2:Attribute Name="groups">{group_values}</saml2:Attribute>'

    # SECURITY: Use cryptographically random IDs instead of predictable timestamps
    response_id = f"_shim_{secrets.token_urlsafe(16)}"
    assertion_id = f"_assert_{secrets.token_urlsafe(16)}"

    root_assertion_xml = f"""<saml2p:Response
    xmlns:saml2p="{NSMAP['saml2p']}"
    xmlns:saml2="{NSMAP['saml2']}"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    Version="2.0">
    <saml2:Assertion xmlns:saml2="{NSMAP['saml2']}" Version="2.0" ID="{assertion_id}" IssueInstant="{now.isoformat()}Z">
        <saml2:Issuer>{issuer}</saml2:Issuer>
        <ds:Signature Id="placeholder"></ds:Signature>
        <saml2:Subject>
            <saml2:NameID Format="{NAMEID_FORMAT}">{html_escape(email) if email else ''}</saml2:NameID>
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
    xmlns:saml2p="{NSMAP['saml2p']}"
    xmlns:saml2="{NSMAP['saml2']}"
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