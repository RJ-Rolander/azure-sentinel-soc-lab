import os

import requests
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

# Two separate OAuth2 resources - a token minted for one is not valid on the
# other, even though it's the same service principal.
MANAGEMENT_SCOPE = "https://management.azure.com/.default"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


def get_token(scope: str) -> dict:
    """Run the client-credentials flow and return the full token response
    (access_token, expires_in, ...) so callers can inspect expiry, not just
    the token string."""
    response = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": scope,
        },
    )
    response.raise_for_status()
    return response.json()


def get_management_token() -> str:
    """Token for the Sentinel incidents REST API (management.azure.com)."""
    return get_token(MANAGEMENT_SCOPE)["access_token"]


def get_log_analytics_token() -> str:
    """Token for querying SecurityEvent directly (api.loganalytics.io)."""
    return get_token(LOG_ANALYTICS_SCOPE)["access_token"]


if __name__ == "__main__":
    for label, scope in [
        ("management.azure.com", MANAGEMENT_SCOPE),
        ("api.loganalytics.io", LOG_ANALYTICS_SCOPE),
    ]:
        token_response = get_token(scope)
        token = token_response["access_token"]
        expires_in = token_response["expires_in"]
        print(f"{label}: OK, expires in {expires_in}s, token starts with {token[:15]}...")
