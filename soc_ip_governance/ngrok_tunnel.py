#!/usr/bin/env python3
"""
Start ngrok tunnel to expose Streamlit app publicly.
Keep this running to maintain the public URL.
"""

from pyngrok import ngrok
import time

# Connect ngrok to port 8501
print("\n" + "="*70)
print("Starting ngrok tunnel...")
print("="*70 + "\n")

public_url = ngrok.connect(8501)

print("✅ PUBLIC SHAREABLE URL:")
print(f"\n   {public_url}\n")
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
