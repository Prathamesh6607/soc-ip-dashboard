@echo off
cd /d "C:\Users\prath\OneDrive\Documents\IP\soc-ip-dashboard"
call venv\Scripts\activate.bat
python -m streamlit run soc_ip_governance\app.py