import os
import secrets
import json
import time
import hashlib
import base64
import re
import html

from datetime import timedelta, datetime
from flask import Flask, render_template, session, redirect, request, url_for, make_response
from functools import wraps
from authlib.integrations.flask_client import OAuth

from shim_utils import jprint
from shim_saml import fetch_cert_and_key, build_saml_response, get_saml_metadata
from shim_scim import push_user_info_to_scim

app = Flask(__name__)

ENVIRONMENT = os.getenv('ENVIRONMENT', 'prod')
# SECURITY: SECRET_KEY must be provided via environment for session persistence across Lambda cold starts
# In local dev, generate a random one; in production, Terraform provides it
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or secrets.token_urlsafe(24)
IS_PROD = ENVIRONMENT.lower().startswith("prod")
DEBUG = not IS_PROD
IS_HTTPS = os.getenv("IS_HTTPS", "f").lower()[0] in ["t", "1"]
COOKIE_PREFIX = "__Host-" if IS_HTTPS else ""
COOKIE_NAME_SESSION = f"{COOKIE_PREFIX}Session-SAML2InternalAccess"

SAML_KEYPAIR_SECRET_NAME = os.getenv("SAML_KEYPAIR_SECRET_NAME", "saml-idp-keypair")
SCIM_URL = os.getenv("SCIM_URL", None)
SCIM_ACCESS_TOKEN = os.getenv("SCIM_ACCESS_TOKEN", None)

app.config.update(
    ENV=ENVIRONMENT,
    SESSION_COOKIE_NAME=COOKIE_NAME_SESSION,
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_HTTPS,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SECRET_KEY=FLASK_SECRET_KEY,
    MAX_CONTENT_LENGTH=120 * 1024 * 1024,
)

CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]

OPENID_CONFIG_URL = os.getenv("OPENID_CONFIG_URL", f"https://sso.service.security.gov.uk/.well-known/openid-configuration?as_app={CLIENT_ID}")
LOGOUT_URL = os.getenv("SIGNOUT_URL", f"https://sso.service.security.gov.uk/sign-out?from_app={CLIENT_ID}")

oauth = OAuth()
oauth.register(
    name="sso",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=OPENID_CONFIG_URL,
    client_kwargs={"scope": "openid profile email"},
)
oauth.init_app(app)

SP_ACS_URL = os.environ["SP_ACS_URL"]
SP_ENTITY_ID = os.environ["SP_ENTITY_ID"]
NAMEID_FORMAT = os.environ.get("NAMEID_FORMAT", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

jprint("Initiated app")

# set no-caching on all response
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
def route_root():
    user_signed_in = session.get("signed_in", False)
    user_email = session.get("user", {}).get("email", "")
    entity_id = request.host_url
    login_url = url_for("route_login", _external=True)
    logout_url = url_for("route_logout", _external=True)
    callback_url = url_for("route_callback", _external=True)
    return f"""<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>SAML2OAuth</title>
  </head>
  <body>
    <h1>SAML2OAuth</h1>
    <p>
        <span>IDP Entity ID: {entity_id}</span></br>
        <span>IDP Login URL: {login_url}</span></br>
        <span>IDP Callback URL: {callback_url}</span></br>
        <a href="{logout_url if user_signed_in else login_url}">{'Logout (' + user_email + ')' if user_signed_in else 'Login'}</a></br>
        <a href="/health/cert">SAML Certificate Health</a></br>
        <a href="/saml/cert">Download SAML Certificate</a></br>
        <a href="/saml/metadata?view=true">View SAML Metadata</a></br>
        <a href="/saml/metadata">Download SAML Metadata</a></br>
    </p>
</body>
</html>"""

@app.route("/health")
def route_health():
    response = make_response("OK")
    return response

@app.route("/health/cert")
def route_health_cert():
    _, IDP_CERT_PEM = fetch_cert_and_key(SAML_KEYPAIR_SECRET_NAME, request.host)
    if IDP_CERT_PEM:
        return "OK"
    return "Not OK", 500

@app.route("/logout", methods=["GET", "POST"])
def route_logout():
    session.clear()
    return redirect(LOGOUT_URL)

@app.route("/login", methods=["GET", "POST"])
def route_login():
    saml_request = request.args.get("SAMLRequest") or request.form.get("SAMLRequest") or None
    relay_state = request.args.get("RelayState") or request.form.get("RelayState") or None

    session["saml_request"] = saml_request
    session["relay_state"] = relay_state

    signed_in = session.get("signed_in", False)
    if signed_in:
        return redirect(url_for("route_saml_response"))

    redirect_uri = url_for('route_callback', _external=True)
    auth_redirect_uri = oauth.sso.authorize_redirect(redirect_uri)
    return auth_redirect_uri

@app.route("/callback", methods=["GET"])
def route_callback():
    token = oauth.sso.authorize_access_token()
    if (
        "userinfo" in token
        and "email_verified" in token["userinfo"]
        and token["userinfo"]["email_verified"]
    ):
        email = token["userinfo"]["email"]
        display_name = token["userinfo"].get("display_name", "")
        if not display_name:
            display_name = email.split("@")[0]
        picture = token["userinfo"].get("picture", "#")

        groups = token["userinfo"].get("groups", [])

        claims = {
            "sub": token.get("sub", token["userinfo"].get("sub")),
            "display_name": display_name,
            "email": email,
            "picture": picture,
            "groups": groups
        }

        family_name = token["userinfo"].get("family_name", None)
        if family_name:
            claims["family_name"] = family_name

        given_name = token["userinfo"].get("given_name", None)
        if given_name:
            claims["given_name"] = given_name

        jprint("Got user info from OAuth", claims)

        session["signed_in"] = True
        session["user"] = claims

        if SCIM_URL and SCIM_ACCESS_TOKEN:
            push_user_info_to_scim(SCIM_URL, SCIM_ACCESS_TOKEN, claims)

        return route_saml_response(signed_in=True, claims=claims)

    return redirect(url_for("route_saml_response"))

@app.route("/saml/response", methods=["GET"])
def route_saml_response(signed_in=False, claims=None):
    if not signed_in:
        signed_in = session.get("signed_in", False)

    if not signed_in:
        return redirect("/error?type=auth-callback-failed")

    if not claims:
        claims = session.get("user", {})

    idp_key, idp_cert = fetch_cert_and_key(SAML_KEYPAIR_SECRET_NAME, request.host)
    issuer = request.host_url
    saml_request_b64 = session.get("saml_request", None)
    relay_state = session.get("relay_state", None)

    saml_response = build_saml_response(
        idp_cert,
        idp_key,
        SP_ACS_URL,
        SP_ENTITY_ID,
        NAMEID_FORMAT,
        claims,
        issuer,
        saml_request_b64=saml_request_b64
    )
    html = build_auto_post_html(SP_ACS_URL, saml_response, relay_state=relay_state)
    return html


def build_auto_post_html(acs_url, saml_response, relay_state=None):
    # SECURITY: Escape relay_state to prevent XSS attacks
    relay_state_html = f"""<input type="hidden" name="RelayState" value="{html.escape(relay_state)}" />""" if relay_state else ""
    return f"""<html>
  <body onload="document.forms[0].submit()">
    <form method="post" action="{acs_url}">
      <input type="hidden" name="SAMLResponse" value="{saml_response}" />
      {relay_state_html}
      <noscript>
        <p>Click continue</p>
        <input type="submit" value="Continue"/>
      </noscript>
    </form>
  </body>
</html>"""


@app.route("/saml/cert")
def route_saml_cert():
    _, IDP_CERT_PEM = fetch_cert_and_key(SAML_KEYPAIR_SECRET_NAME, request.host)
    if IDP_CERT_PEM:
        response = make_response(IDP_CERT_PEM)
        response.headers["Content-Type"] = "application/x-x509-ca-der"
        return response
    return "No certificate found", 404


@app.route("/saml/metadata")
def route_saml_metadata():
    login_url = url_for("route_login", _external=True)
    logout_url = url_for("route_logout", _external=True)

    xml = get_saml_metadata(login_url, logout_url, request.host_url, NAMEID_FORMAT, SAML_KEYPAIR_SECRET_NAME, request.host)

    if request.args.get("view") == "true":
        escaped_xml = html.escape(xml)
        response = f"""<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>SAML Metadata</title>
  </head>
  <body>
    <h1>SAML Metadata</h1>
    <pre>{escaped_xml}</pre>
  </body>
</html>"""
    else:
        response = make_response(xml)
        response.headers["Content-Type"] = "application/saml+xml"
    return response, 200
