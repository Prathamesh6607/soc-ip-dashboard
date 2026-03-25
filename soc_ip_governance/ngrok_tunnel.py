#!/usr/bin/env python3
"""
Start ngrok tunnel to expose Streamlit app publicly.
Keep this running to maintain the public URL.
"""

from pathlib import Path
from pyngrok import ngrok
from pyngrok.exception import PyngrokNgrokError
import os
import sys
import time

DEFAULT_STATIC_DOMAIN = "watchful-blakely-undetestably.ngrok-free.dev"


def load_static_domain():
    env_domain = os.getenv("NGROK_STATIC_DOMAIN", "").strip()
    if env_domain:
        return env_domain

    workspace_domain_file = Path(__file__).resolve().parent.parent / ".ngrok_domain"
    if workspace_domain_file.exists():
        file_value = workspace_domain_file.read_text(encoding="utf-8").strip()
        if file_value:
            return file_value

    return DEFAULT_STATIC_DOMAIN


def connect_http_tunnel(static_domain=None):
    if static_domain:
        return ngrok.connect(8501, domain=static_domain)
    return ngrok.connect(8501)

# Connect ngrok to port 8501
print("\n" + "="*70)
print("Starting ngrok tunnel...")
print("="*70 + "\n")

public_url = None
static_domain = load_static_domain()

try:
    public_url = connect_http_tunnel(static_domain=static_domain)
except PyngrokNgrokError as error:
    error_text = str(error)
    if "already online" in error_text or "ERR_NGROK_334" in error_text:
        print("⚠️ Static domain is already online (ERR_NGROK_334).")
        print(f"Domain: https://{static_domain}")
        print("Falling back to an auto-generated public ngrok URL...")
        print("(To reuse static domain, stop old session at https://dashboard.ngrok.com/agents)")
        try:
            public_url = connect_http_tunnel()
        except PyngrokNgrokError as second_error:
            print("❌ Could not start ngrok tunnel with fallback URL.")
            print(str(second_error))
            sys.exit(5)
    elif "ERR_NGROK_3200" in error_text or "domain" in error_text.lower():
        print("⚠️ Static domain is unavailable or invalid.")
        print(f"Tried: https://{static_domain}")
        print("Falling back to an auto-generated public ngrok URL...")
        try:
            public_url = connect_http_tunnel()
        except PyngrokNgrokError as second_error:
            print("❌ Could not start ngrok tunnel with fallback URL.")
            print(str(second_error))
            sys.exit(6)
    elif "ERR_NGROK_4018" in error_text or "authtoken" in error_text.lower():
        print("❌ Ngrok authentication is not configured (ERR_NGROK_4018).\n")
        print("Fix steps:")
        print("1) Create/verify account: https://dashboard.ngrok.com/signup")
        print("2) Copy token from: https://dashboard.ngrok.com/get-started/your-authtoken")
        print("3) Run this command:\n")
        print("   python -c \"from pyngrok import ngrok; ngrok.set_auth_token('YOUR_NGROK_AUTHTOKEN')\"\n")
        print("4) Re-run the launcher: ./run_dashboard.sh\n")
        sys.exit(2)
    else:
        print("❌ Could not start ngrok tunnel.")
        print(error_text)
        sys.exit(3)

if public_url is None:
    print("❌ Tunnel start failed.")
    sys.exit(4)

tunnel_url = getattr(public_url, "public_url", str(public_url)).strip()

print("✅ PUBLIC SHAREABLE URL:")
print(f"\n   {tunnel_url}\n")
if static_domain and static_domain in tunnel_url:
    print(f"✅ STATIC URL TARGET: https://{static_domain}")
elif static_domain:
    print(f"⚠️ Static domain not active right now: https://{static_domain}")
    print("✅ Use the PUBLIC SHAREABLE URL shown above.")
print("="*70)
print("\n✅ SHARE THIS URL WITH YOUR FRIENDS")
print("✅ Keep this terminal open to maintain the tunnel")
print("✅ Press Ctrl+C to stop the tunnel\n")
print("="*70 + "\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n\n❌ Ngrok tunnel closed.")
    ngrok.kill()
