#!/usr/bin/env python3
"""
Start ngrok tunnel to expose Streamlit app publicly.
Keep this running to maintain the public URL.
"""

from pyngrok import ngrok
from pyngrok.exception import PyngrokNgrokError
import sys
import time

STATIC_DOMAIN = "watchful-blakely-undetestably.ngrok-free.dev"


def connect_http_tunnel():
    return ngrok.connect(8501, domain=STATIC_DOMAIN)

# Connect ngrok to port 8501
print("\n" + "="*70)
print("Starting ngrok tunnel...")
print("="*70 + "\n")

public_url = None

try:
    public_url = connect_http_tunnel()
except PyngrokNgrokError as error:
    error_text = str(error)
    if "already online" in error_text or "ERR_NGROK_334" in error_text:
        print("❌ Static domain is already online (ERR_NGROK_334).")
        print(f"Domain: https://{STATIC_DOMAIN}")
        print("Stop the existing ngrok agent/session using this domain in dashboard:")
        print("https://dashboard.ngrok.com/agents")
        print("Then rerun: ./run_dashboard.sh")
        sys.exit(5)
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

print("✅ PUBLIC SHAREABLE URL:")
print(f"\n   {public_url}\n")
print(f"✅ STATIC URL TARGET: https://{STATIC_DOMAIN}")
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
