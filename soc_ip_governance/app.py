"""Streamlit SOC IP Governance Automation dashboard."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from abuseipdb import query_abuseipdb
from config import CONFIG
from database import (
    fetch_scan_results,
    fetch_detected_threats,
    fetch_custom_whitelist_entries,
    init_database,
    update_approval_status,
    upsert_scan_result,
    upsert_detected_threat,
    upsert_custom_whitelist_entry,
    delete_custom_whitelist_entry,
    update_scan_result_path,
    clear_all_scan_results,
)
from ip_validator import extract_valid_ips, generate_summary_stats, remove_duplicates
from gmail_auth import authenticate_gmail, clear_authentication, get_authenticated_email
from email_notifier import (
    build_approval_html,
    build_approval_subject,
    parse_email_list,
    send_approval_email,
)
from master_sheet import (
    append_to_master_sheet,
    filter_already_blocked,
    load_master_blocked_ips,
    read_master_sheet_rows,
    update_master_sheet_row,
    delete_master_sheet_row,
)
from whitelist import (
    classify_whitelist_entry,
    load_whitelist_entries,
    filter_whitelisted_ips,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Use project root for SOAR runtime files
PROJECT_ROOT = Path(__file__).parent.parent
SOAR_PID_FILE = PROJECT_ROOT / ".soar_module.pid"
SOAR_RUNTIME_LOG = PROJECT_ROOT / "soar_runtime.log"


def _read_soar_pid() -> int | None:
    if not SOAR_PID_FILE.exists():
        return None
    try:
        value = SOAR_PID_FILE.read_text(encoding="utf-8").strip()
        return int(value) if value else None
    except Exception:
        return None


def _is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def is_soar_running() -> bool:
    pid = _read_soar_pid()
    if not pid:
        return False
    if _is_process_running(pid):
        return True
    try:
        SOAR_PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return False


def start_soar_module_process() -> tuple[bool, str]:
    if is_soar_running():
        return False, "SOAR module is already running."

    soar_script_path = Path(__file__).parent / "cloudflare_soar_module.py"
    if not soar_script_path.exists():
        return False, f"SOAR script not found: {soar_script_path}"

    # Use project root (parent of soc_ip_governance/) to find logpush file
    project_root = Path(__file__).parent.parent
    logpush_path = project_root / "logpush_simulation.json"
    
    # Build environment with auto-config
    env = os.environ.copy()
    if not env.get("LOG_INPUT_PATH"):
        # Set LOG_INPUT_PATH to project root, let module find the file with LOG_GLOB
        env["LOG_INPUT_PATH"] = str(project_root)
        env["LOG_GLOB"] = "logpush_simulation.json"
    if not env.get("SQLITE_DB_PATH"):
        env["SQLITE_DB_PATH"] = str(CONFIG.sqlite_path)
    if not env.get("CLOUDFLARE_API_TOKEN") or not env.get("ZONE_ID"):
        env["DEMO_MODE"] = "1"
        logger.info("Starting SOAR in DEMO mode (no Cloudflare credentials)")
    # Pass AbuseIPDB API key to SOAR module for ISP enrichment
    if not env.get("ABUSEIPDB_API_KEY") and CONFIG.abuseipdb_api_key:
        env["ABUSEIPDB_API_KEY"] = CONFIG.abuseipdb_api_key

    try:
        runtime_log_handle = SOAR_RUNTIME_LOG.open("a", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, str(soar_script_path)],
            cwd=str(Path(__file__).parent.parent),
            stdout=runtime_log_handle,
            stderr=runtime_log_handle,
            env=env,
            start_new_session=True,
        )
        SOAR_PID_FILE.write_text(str(process.pid), encoding="utf-8")
        mode = "DEMO" if env.get("DEMO_MODE") == "1" else "PRODUCTION"
        return True, f"Started SOAR module in {mode} mode with PID {process.pid}. Detections will appear in 'Detected Threats' tab."
    except Exception as exc:
        return False, f"Failed to start SOAR module: {exc}"


def stop_soar_module_process() -> tuple[bool, str]:
    pid = _read_soar_pid()
    if not pid:
        return False, "SOAR module is not running."

    try:
        os.kill(pid, 15)
        deadline = time.time() + 3
        while time.time() < deadline:
            if not _is_process_running(pid):
                break
            time.sleep(0.1)

        if _is_process_running(pid):
            os.kill(pid, 9)

        SOAR_PID_FILE.unlink(missing_ok=True)
        return True, f"Stopped SOAR module process PID {pid}."
    except ProcessLookupError:
        SOAR_PID_FILE.unlink(missing_ok=True)
        return True, "SOAR process was already stopped."
    except Exception as exc:
        return False, f"Failed to stop SOAR module: {exc}"


def initialize_state() -> None:
    """Initialize Streamlit session state and SQLite store."""

    init_database(CONFIG.sqlite_path)

    if "processing_summary" not in st.session_state:
        st.session_state.processing_summary = {}
    if "final_ips_checked" not in st.session_state:
        st.session_state.final_ips_checked = []
    if "invalid_entries" not in st.session_state:
        st.session_state.invalid_entries = []
    if "whitelisted_entries" not in st.session_state:
        st.session_state.whitelisted_entries = []
    if "api_failed_checks" not in st.session_state:
        st.session_state.api_failed_checks = 0


def process_raw_input(raw_text: str, threshold: int, progress_bar=None, status_text=None) -> None:
    """Run full passive SOC processing pipeline for multiline input."""

    if status_text:
        status_text.text("Extracting and validating IPs...")
    valid_ips, invalid_entries, total_lines = extract_valid_ips(raw_text)
    unique_valid_ips, duplicate_count = remove_duplicates(valid_ips)

    if status_text:
        status_text.text("Loading whitelist and master sheet...")
    # Load and apply whitelist filtering (file + custom table)
    file_individual_ips, file_cidr_blocks = load_whitelist_entries(CONFIG.whitelist_sheet_path)
    custom_entries = fetch_custom_whitelist_entries(CONFIG.sqlite_path)
    custom_individual_ips = {entry["entry"] for entry in custom_entries if entry.get("entry_type") == "IP"}
    custom_cidr_blocks = {entry["entry"] for entry in custom_entries if entry.get("entry_type") == "CIDR"}

    individual_ips = file_individual_ips | custom_individual_ips
    cidr_blocks = file_cidr_blocks | custom_cidr_blocks

    non_whitelisted_ips, whitelisted_ips, whitelist_count = filter_whitelisted_ips(
        unique_valid_ips, individual_ips, cidr_blocks
    )

    blocked_ips = load_master_blocked_ips(CONFIG.master_sheet_path)
    new_ips, already_blocked_count = filter_already_blocked(non_whitelisted_ips, blocked_ips)

    detected_threats: list[dict] = []
    api_failed_checks = 0
    total_to_check = len(new_ips)
    
    for idx, ip_addr in enumerate(new_ips, start=1):
        if status_text:
            status_text.text(f"Querying AbuseIPDB for {ip_addr} ({idx}/{total_to_check})...")
        if progress_bar and total_to_check > 0:
            progress_bar.progress(idx / total_to_check)
            
        enriched = query_abuseipdb(
            ip_address=ip_addr,
            api_key=CONFIG.abuseipdb_api_key,
            api_url=CONFIG.abuseipdb_url,
            timeout_seconds=CONFIG.timeout_seconds,
            max_retries=CONFIG.max_retries,
            retry_backoff_seconds=CONFIG.retry_backoff_seconds,
        )
        if not enriched:
            api_failed_checks += 1
            continue

        # For AbuseIPDB scans, set country field to the same as countryCode
        enriched["country"] = enriched.get("countryCode", "")
        upsert_scan_result(CONFIG.sqlite_path, enriched)

        if int(enriched.get("abuseConfidenceScore", 0)) >= threshold:
            enriched["Approval Status"] = "Pending"
            detected_threats.append(enriched)
            upsert_detected_threat(CONFIG.sqlite_path, enriched)

    summary = generate_summary_stats(
        total_lines=total_lines,
        valid_ips=valid_ips,
        invalid_entries=invalid_entries,
        duplicate_count=duplicate_count,
        already_blocked_count=already_blocked_count,
        ips_checked=len(new_ips),
        detected_count=len(detected_threats),
    )

    # Add whitelist count to summary
    summary["Whitelisted IPs"] = whitelist_count

    st.session_state.processing_summary = summary
    st.session_state.final_ips_checked = new_ips
    st.session_state.invalid_entries = invalid_entries
    st.session_state.whitelisted_entries = whitelisted_ips
    st.session_state.api_failed_checks = api_failed_checks
    
    if status_text:
        status_text.text("✅ Processing completed!")
    if progress_bar:
        progress_bar.progress(1.0)


def render_summary_cards(summary: dict[str, int]) -> None:
    """Render required summary metrics on UI."""

    if not summary:
        st.info("No processing run yet.")
        return

    metric_labels = list(summary.keys())
    columns = st.columns(min(4, len(metric_labels)))

    for index, label in enumerate(metric_labels):
        columns[index % len(columns)].metric(label=label, value=summary[label])


def render_tab_raw_input() -> None:
    """Tab 1: Raw input processing."""

    st.subheader("Raw Input Processing")
    st.caption("Paste multiline IP list. Invalid lines are ignored automatically. Whitelisted IPs are filtered out.")

    default_input = "\n".join(
        [
            "167.103.26.254",
            "162.10.221.11",
            "44.64k",
            "35.244.50.242",
            "44.58k",
            "2407:3640:2291:9176::1",
        ]
    )

    raw_text = st.text_area("Multiline IP Input", value=default_input, height=220)
    threshold = st.number_input("Abuse confidence threshold", min_value=0, max_value=100, value=CONFIG.confidence_threshold)

    if st.button("Process IPs", type="primary"):
        progress_bar = st.progress(0.0)
        status_text = st.empty()
        
        process_raw_input(
            raw_text=raw_text,
            threshold=int(threshold),
            progress_bar=progress_bar,
            status_text=status_text,
        )
        
        status_text.empty()
        progress_bar.empty()
        st.success("Processing completed.")

    render_summary_cards(st.session_state.processing_summary)

    if st.session_state.final_ips_checked:
        st.write("Final IPs sent to AbuseIPDB (after filtering)")
        st.code("\n".join(st.session_state.final_ips_checked), language="text")

    if st.session_state.whitelisted_entries:
        st.info(f"**Whitelisted IPs Filtered:** {len(st.session_state.whitelisted_entries)} IP(s) were filtered as they are in the whitelist")
        with st.expander("View Whitelisted IPs"):
            st.code("\n".join(st.session_state.whitelisted_entries), language="text")

    if st.session_state.invalid_entries:
        st.write("Invalid entries removed")
        st.code("\n".join(st.session_state.invalid_entries), language="text")

    if st.session_state.api_failed_checks:
        st.warning(f"AbuseIPDB checks failed for {st.session_state.api_failed_checks} IPs. See logs for details.")


def render_tab_detected_threats() -> None:
    """Tab 2: Show detected threats and approval workflow."""

    st.subheader("Detected Threats")
    st.caption("Shows threats from AbuseIPDB scans and Cloudflare SOAR detections")

    min_abuse_score = st.slider(
        "Minimum Abuse Confidence Score to Display",
        min_value=0,
        max_value=100,
        value=20,
        step=1,
        help="Show only IPs with abuse score >= this value (or all SOAR detections)",
    )

    scanned_results = fetch_scan_results(CONFIG.sqlite_path, min_score=min_abuse_score)
    threats = fetch_detected_threats(CONFIG.sqlite_path)
    
    if scanned_results:
        st.markdown(f"### All Scanned IPs (Abuse Score ≥ {min_abuse_score})")
        
        col1, col2 = st.columns([10, 2])
        col1.write("")
        clear_btn = col2.button("🗑️ Clear All Results", key="clear_all_results")
        
        if clear_btn:
            deleted_count = clear_all_scan_results(CONFIG.sqlite_path)
            st.success(f"Cleared {deleted_count} scan results.")
            st.rerun()
        
        threat_rows = fetch_detected_threats(CONFIG.sqlite_path)
        status_map = {
            row["ipAddress"]: row.get("Approval Status", "Pending")
            for row in threat_rows
        }

        # Separate IPs by source
        abuseipdb_results = [r for r in scanned_results if r.get("countryCode") != "SOAR"]
        soar_results = [r for r in scanned_results if r.get("countryCode") == "SOAR"]
        
        # Display AbuseIPDB table
        if abuseipdb_results:
            st.markdown(f"#### 🌐 AbuseIPDB Scanned IPs ({len(abuseipdb_results)} IPs)")
            scanned_by_ip_abuse = {row["ipAddress"]: row for row in abuseipdb_results}

            bulk_col1, bulk_col2 = st.columns([3, 2])
            with bulk_col1:
                bulk_status_abuse_scan = st.selectbox(
                    "Select All Approval Status (AbuseIPDB Scanned)",
                    ["Pending", "Approved", "Rejected"],
                    index=0,
                    key=f"bulk_status_abuse_scan_{min_abuse_score}",
                )
            with bulk_col2:
                if st.button("Apply to All", key=f"btn_bulk_abuse_scan_{min_abuse_score}"):
                    updated_count = 0
                    for ip_addr, base_row in scanned_by_ip_abuse.items():
                        upsert_detected_threat(
                            CONFIG.sqlite_path,
                            {
                                "ipAddress": ip_addr,
                                "abuseConfidenceScore": int(base_row.get("abuseConfidenceScore", 0)),
                                "countryCode": base_row.get("countryCode", ""),
                                "isp": base_row.get("isp", ""),
                                "PATH": str(base_row.get("PATH") or "").strip(),
                                "Approval Status": bulk_status_abuse_scan,
                            },
                        )
                        updated_count += 1
                    st.success(f"Updated {updated_count} AbuseIPDB scanned IP(s) to {bulk_status_abuse_scan}.")
                    st.rerun()

            abuseipdb_df = pd.DataFrame(abuseipdb_results)[["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH"]]
            abuseipdb_df["Approval Status"] = abuseipdb_df["ipAddress"].map(lambda ip: status_map.get(ip, "Pending"))
            
            original_path_map_abuse = {row["ipAddress"]: (row.get("PATH") or "") for row in abuseipdb_results}
            original_status_map_abuse = {row["ipAddress"]: status_map.get(row["ipAddress"], "Pending") for row in abuseipdb_results}

            edited_abuseipdb_df = st.data_editor(
                abuseipdb_df,
                width="stretch",
                hide_index=True,
                disabled=["ipAddress", "abuseConfidenceScore", "countryCode", "isp"],
                column_config={
                    "ipAddress": st.column_config.TextColumn("IP Address", width="medium"),
                    "abuseConfidenceScore": st.column_config.NumberColumn("Abuse Score", width="small"),
                    "countryCode": st.column_config.TextColumn("Country", width="small"),
                    "isp": st.column_config.TextColumn("ISP", width="medium"),
                    "PATH": st.column_config.TextColumn("PATH", help="Editable path value"),
                    "Approval Status": st.column_config.SelectboxColumn(
                        "Approval Status",
                        options=["Pending", "Approved", "Rejected"],
                        help="Editable status",
                    )
                },
                key=f"abuseipdb_scan_editor_{min_abuse_score}",
            )

            for _, row in edited_abuseipdb_df.iterrows():
                ip_addr = row["ipAddress"]
                new_path = str(row.get("PATH") or "").strip()
                old_path = str(original_path_map_abuse.get(ip_addr, "")).strip()
                new_status = str(row.get("Approval Status") or "Pending").strip()
                old_status = str(original_status_map_abuse.get(ip_addr, "Pending")).strip()

                if new_path != old_path:
                    update_scan_result_path(CONFIG.sqlite_path, ip_addr, new_path)

                if new_status != old_status:
                    base_row = scanned_by_ip_abuse.get(ip_addr, {})
                    upsert_detected_threat(
                        CONFIG.sqlite_path,
                        {
                            "ipAddress": ip_addr,
                            "abuseConfidenceScore": int(base_row.get("abuseConfidenceScore", 0)),
                            "countryCode": base_row.get("countryCode", ""),
                            "isp": base_row.get("isp", ""),
                            "PATH": new_path,
                            "Approval Status": new_status,
                        },
                    )
        
        # Display SOAR table
        if soar_results:
            st.markdown(f"#### 🔍 SOAR Logpush Detected IPs ({len(soar_results)} IPs)")
            scanned_by_ip_soar = {row["ipAddress"]: row for row in soar_results}

            bulk_col1, bulk_col2 = st.columns([3, 2])
            with bulk_col1:
                bulk_status_soar_scan = st.selectbox(
                    "Select All Approval Status (SOAR Scanned)",
                    ["Pending", "Approved", "Rejected"],
                    index=0,
                    key=f"bulk_status_soar_scan_{min_abuse_score}",
                )
            with bulk_col2:
                if st.button("Apply to All", key=f"btn_bulk_soar_scan_{min_abuse_score}"):
                    updated_count = 0
                    for ip_addr, base_row in scanned_by_ip_soar.items():
                        upsert_detected_threat(
                            CONFIG.sqlite_path,
                            {
                                "ipAddress": ip_addr,
                                "abuseConfidenceScore": int(base_row.get("abuseConfidenceScore", 0)),
                                "countryCode": "SOAR",
                                "isp": base_row.get("isp", ""),
                                "PATH": str(base_row.get("PATH") or "").strip(),
                                "Approval Status": bulk_status_soar_scan,
                            },
                        )
                        updated_count += 1
                    st.success(f"Updated {updated_count} SOAR scanned IP(s) to {bulk_status_soar_scan}.")
                    st.rerun()

            soar_df = pd.DataFrame(soar_results)[["ipAddress", "abuseConfidenceScore", "country", "isp", "PATH"]]
            soar_df.rename(columns={"abuseConfidenceScore": "Request Count"}, inplace=True)
            soar_df["Approval Status"] = soar_df["ipAddress"].map(lambda ip: status_map.get(ip, "Pending"))
            
            original_path_map_soar = {row["ipAddress"]: (row.get("PATH") or "") for row in soar_results}
            original_status_map_soar = {row["ipAddress"]: status_map.get(row["ipAddress"], "Pending") for row in soar_results}

            edited_soar_df = st.data_editor(
                soar_df,
                width="stretch",
                hide_index=True,
                disabled=["ipAddress", "Request Count", "country", "isp"],
                column_config={
                    "ipAddress": st.column_config.TextColumn("IP Address", width="medium"),
                    "Request Count": st.column_config.NumberColumn("Requests", width="small"),
                    "country": st.column_config.TextColumn("Country", width="small"),
                    "isp": st.column_config.TextColumn("ISP", width="medium"),
                    "PATH": st.column_config.TextColumn("Malicious Paths", help="Top 5 detected paths"),
                    "Approval Status": st.column_config.SelectboxColumn(
                        "Approval Status",
                        options=["Pending", "Approved", "Rejected"],
                        help="Editable status",
                    )
                },
                key=f"soar_scan_editor_{min_abuse_score}",
            )

            for _, row in edited_soar_df.iterrows():
                ip_addr = row["ipAddress"]
                new_path = str(row.get("PATH") or "").strip()
                old_path = str(original_path_map_soar.get(ip_addr, "")).strip()
                new_status = str(row.get("Approval Status") or "Pending").strip()
                old_status = str(original_status_map_soar.get(ip_addr, "Pending")).strip()

                if new_path != old_path:
                    update_scan_result_path(CONFIG.sqlite_path, ip_addr, new_path)

                if new_status != old_status:
                    base_row = scanned_by_ip_soar.get(ip_addr, {})
                    upsert_detected_threat(
                        CONFIG.sqlite_path,
                        {
                            "ipAddress": ip_addr,
                            "abuseConfidenceScore": int(base_row.get("abuseConfidenceScore", 0)),
                            "countryCode": "SOAR",
                            "isp": base_row.get("isp", ""),
                            "PATH": new_path,
                            "Approval Status": new_status,
                        },
                    )
    
    # Always check for threats, even if no scan results
    threats = fetch_detected_threats(CONFIG.sqlite_path)
    
    if not scanned_results and not threats:
        st.info(f"No scan results with abuse score >= {min_abuse_score}. Process IPs in Tab 1 or start SOAR module in Cloudflare SOAR tab.")
        if is_soar_running():
            st.success("✅ SOAR module is running. Detections will appear here as threats are found.")
        return
    
    if not scanned_results and threats:
        st.info(f"No AbuseIPDB scan results with abuse score >= {min_abuse_score}, but showing {len(threats)} SOAR detections below.")
    
    if not threats:
        st.info("No detected threats yet. Threats will appear here once identified.")
        return

    st.markdown("### Detected Threats (Above Threshold)")
    
    # Show detection source breakdown
    soar_count = sum(1 for t in threats if t.get("countryCode") == "SOAR")
    abuseipdb_count = len(threats) - soar_count
    
    summary_col1, summary_col2, summary_col3 = st.columns(3)
    with summary_col1:
        st.metric("Total Threats", len(threats))
    with summary_col2:
        st.metric("🌐 AbuseIPDB", abuseipdb_count)
    with summary_col3:
        st.metric("🔍 SOAR Logpush", soar_count)

    # Separate threats by source
    abuseipdb_threats = [t for t in threats if t.get("countryCode") != "SOAR"]
    soar_threats = [t for t in threats if t.get("countryCode") == "SOAR"]
    
    # Display AbuseIPDB threats table
    if abuseipdb_threats:
        st.markdown(f"#### 🌐 AbuseIPDB Detected Threats ({len(abuseipdb_threats)} IPs)")

        bulk_col1, bulk_col2 = st.columns([3, 2])
        with bulk_col1:
            bulk_status_abuse_threats = st.selectbox(
                "Select All Approval Status (AbuseIPDB Threats)",
                ["Pending", "Approved", "Rejected"],
                index=0,
                key="bulk_status_abuse_threats",
            )
        with bulk_col2:
            if st.button("Apply to All", key="btn_bulk_abuse_threats"):
                for threat in abuseipdb_threats:
                    ip_addr = str(threat.get("ipAddress", "")).strip()
                    if ip_addr:
                        update_approval_status(CONFIG.sqlite_path, ip_addr, bulk_status_abuse_threats)
                st.success(f"Updated {len(abuseipdb_threats)} AbuseIPDB threat IP(s) to {bulk_status_abuse_threats}.")
                st.rerun()
        
        abuseipdb_df = pd.DataFrame(abuseipdb_threats)
        
        # Ensure all required columns exist
        for col in ["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH", "Approval Status"]:
            if col not in abuseipdb_df.columns:
                abuseipdb_df[col] = ""
        
        # Display only relevant columns
        display_cols_abuse = ["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH", "Approval Status"]
        
        edited_abuseipdb_threats_df = st.data_editor(
            abuseipdb_df[display_cols_abuse],
            width="stretch",
            hide_index=True,
            disabled=["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH"],
            column_config={
                "ipAddress": st.column_config.TextColumn("IP Address", width="medium"),
                "abuseConfidenceScore": st.column_config.NumberColumn("Abuse Score", width="small"),
                "countryCode": st.column_config.TextColumn("Country", width="small"),
                "isp": st.column_config.TextColumn("ISP", width="medium"),
                "PATH": st.column_config.TextColumn("Details", width="large"),
                "Approval Status": st.column_config.SelectboxColumn(
                    "Approval Status",
                    options=["Pending", "Approved", "Rejected"],
                    width="small",
                ),
            },
            key="abuseipdb_threats_editor",
        )
        
        # Auto-save status changes for AbuseIPDB threats
        for idx, row in edited_abuseipdb_threats_df.iterrows():
            ip_addr = str(row["ipAddress"])
            new_status = str(row.get("Approval Status", "Pending"))
            old_status = abuseipdb_threats[idx].get("Approval Status", "Pending")
            
            if new_status != old_status:
                update_approval_status(CONFIG.sqlite_path, ip_addr, new_status)
                st.success(f"Updated {ip_addr} status to {new_status}")
                st.rerun()
    
    # Display SOAR threats table
    if soar_threats:
        st.markdown(f"#### 🔍 SOAR Logpush Detected Threats ({len(soar_threats)} IPs)")

        bulk_col1, bulk_col2 = st.columns([3, 2])
        with bulk_col1:
            bulk_status_soar_threats = st.selectbox(
                "Select All Approval Status (SOAR Threats)",
                ["Pending", "Approved", "Rejected"],
                index=0,
                key="bulk_status_soar_threats",
            )
        with bulk_col2:
            if st.button("Apply to All", key="btn_bulk_soar_threats"):
                for threat in soar_threats:
                    ip_addr = str(threat.get("ipAddress", "")).strip()
                    if ip_addr:
                        update_approval_status(CONFIG.sqlite_path, ip_addr, bulk_status_soar_threats)
                st.success(f"Updated {len(soar_threats)} SOAR threat IP(s) to {bulk_status_soar_threats}.")
                st.rerun()
        
        soar_df = pd.DataFrame(soar_threats)
        
        # Ensure all required columns exist
        for col in ["ipAddress", "abuseConfidenceScore", "country", "isp", "PATH", "Approval Status"]:
            if col not in soar_df.columns:
                soar_df[col] = ""
        
        # Rename abuseConfidenceScore to Request Count for SOAR
        soar_df_display = soar_df[["ipAddress", "abuseConfidenceScore", "country", "isp", "PATH", "Approval Status"]].copy()
        soar_df_display.rename(columns={"abuseConfidenceScore": "Request Count"}, inplace=True)
        
        edited_soar_threats_df = st.data_editor(
            soar_df_display,
            width="stretch",
            hide_index=True,
            disabled=["ipAddress", "Request Count", "country", "isp", "PATH"],
            column_config={
                "ipAddress": st.column_config.TextColumn("IP Address", width="medium"),
                "Request Count": st.column_config.NumberColumn("Requests", width="small"),
                "country": st.column_config.TextColumn("Country", width="small"),
                "isp": st.column_config.TextColumn("ISP", width="medium"),
                "PATH": st.column_config.TextColumn("Malicious Paths", width="large"),
                "Approval Status": st.column_config.SelectboxColumn(
                    "Approval Status",
                    options=["Pending", "Approved", "Rejected"],
                    width="small",
                ),
            },
            key="soar_threats_editor",
        )
        
        # Auto-save status changes for SOAR threats
        for idx, row in edited_soar_threats_df.iterrows():
            ip_addr = str(row["ipAddress"])
            new_status = str(row.get("Approval Status", "Pending"))
            old_status = soar_threats[idx].get("Approval Status", "Pending")
            
            if new_status != old_status:
                update_approval_status(CONFIG.sqlite_path, ip_addr, new_status)
                st.success(f"Updated {ip_addr} status to {new_status}")
                st.rerun()

    st.divider()
    st.markdown("### Approval Actions")

    sender_email = st.session_state.get("authenticated_email", "")
    receiver_email = CONFIG.approval_receiver_email
    monitoring_list = parse_email_list(CONFIG.monitoring_emails)

    if sender_email:
        st.caption(f"Authenticated sender: {sender_email} | Receiver: {receiver_email}")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        approver_name = st.selectbox(
            "Approver Name",
            ["Priyanka Maam", "Pankaj Sir"],
            index=0,
        )
    with col2:
        soc_analyst_name = st.text_input("SOC Analyst Name", value="Shift Member Name")
    with col3:
        shift = st.selectbox(
            "Shift",
            ["Morning", "Afternoon", "Night"],
            index=0,
        )
    with col4:
        default_notes = st.text_input("Default Notes", value="Approved by SOC")

    st.caption("SSO mode: emails are sent via authenticated Gmail account.")

    test_col1, test_col2 = st.columns([2, 5])
    with test_col1:
        if st.button("Send Test Email", key="btn_send_test_email"):
            sample_record = {
                "ipAddress": threats[0].get("ipAddress", "0.0.0.0"),
                "abuseConfidenceScore": threats[0].get("abuseConfidenceScore", 0),
                "countryCode": threats[0].get("countryCode", ""),
                "isp": threats[0].get("isp", ""),
                "PATH": threats[0].get("PATH", ""),
                "Reason": CONFIG.default_reason,
            }

            test_subject = build_approval_subject(shift=shift, block_date=datetime.now())
            test_body = build_approval_html(
                approver_name=approver_name,
                shift=shift,
                approved_ips=[sample_record],
            )

            sent, test_msg = send_approval_email(
                smtp_host="",
                smtp_port=0,
                smtp_username="",
                smtp_password="",
                smtp_use_tls=True,
                email_from=sender_email,
                email_to=[receiver_email],
                monitoring_emails=monitoring_list,
                subject=f"[TEST] {test_subject}",
                html_body=test_body,
                provider="gmail_api",
                gmail_credentials_file=CONFIG.gmail_credentials_file,
                gmail_token_file=CONFIG.gmail_token_file,
                gmail_user_id=CONFIG.gmail_user_id,
            )

            if sent:
                st.success(test_msg)
            else:
                st.warning(test_msg)
    with test_col2:
        st.caption("Sends a test approval email using current SMTP settings and selected approver/shift.")

    st.markdown("### Update Individual IP Status")
    st.caption("Approval Status is now editable inline in the scanned results table beside PATH.")

    st.divider()
    st.markdown("### Bulk Action: Add All Approved IPs to Master Block List")
    
    # Fetch all approved threats
    all_threats = fetch_detected_threats(CONFIG.sqlite_path)
    approved_threats = [t for t in all_threats if t.get("Approval Status") == "Approved"]
    
    if approved_threats:
        st.info(f"**{len(approved_threats)} IP(s) ready to be added to Master Blocking Sheet and notified via email.**")

        @st.dialog("Confirm Clear Approved List")
        def confirm_clear_approved_dialog() -> None:
            st.warning("This will move all currently Approved IPs back to Pending.")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("✅ Confirm Clear", key="confirm_clear_approved_yes"):
                    converted_count = 0
                    for threat in approved_threats:
                        ip_addr = threat.get("ipAddress", "")
                        if not ip_addr:
                            continue
                        update_approval_status(CONFIG.sqlite_path, ip_addr, "Pending")
                        converted_count += 1
                    st.success(f"Converted {converted_count} approved IP(s) to Pending.")
                    st.rerun()
            with c2:
                st.button("Cancel", key="confirm_clear_approved_no")
        
        # Display approved IPs summary
        with st.expander("View Approved IPs to be Added", expanded=True):
            approved_df = pd.DataFrame(approved_threats)
            st.dataframe(
                approved_df[["ipAddress", "abuseConfidenceScore", "country", "isp", "PATH"]],
                width="stretch",
                hide_index=True,
                column_config={
                    "ipAddress": "IP Address",
                    "abuseConfidenceScore": "Abuse Score",
                    "country": "Country",
                    "isp": "ISP",
                    "PATH": "PATH",
                },
            )
        
        # Bulk actions
        col1, col2, col3 = st.columns([2, 2, 4])
        with col1:
            if st.button("✅ Send & Add All to Master Block List", key="btn_bulk_approve", type="primary"):
                # Track added IPs
                added_ips = []
                failed_ips = []
                
                # Add all approved IPs to master sheet
                for threat in approved_threats:
                    ip_addr = threat.get("ipAddress", "")
                    appended = append_to_master_sheet(
                        master_csv_path=Path(CONFIG.master_sheet_path),
                        name=soc_analyst_name,
                        ip_address=ip_addr,
                        notes=default_notes,
                        shift=shift,
                        reason=CONFIG.default_reason,
                        approval_status="Approved",
                        country=threat.get("country", ""),
                        isp=threat.get("isp", ""),
                        abusive_percentage=str(threat.get("abuseConfidenceScore", "NA")),
                        final_status="Blocked",
                        selection_flag="FALSE",
                    )
                    if appended:
                        added_ips.append(threat)
                    else:
                        failed_ips.append(ip_addr)
                
                # Prepare bulk email with all added IPs
                if added_ips:
                    subject = build_approval_subject(shift=shift, block_date=datetime.now())
                    html_body = build_approval_html(
                        approver_name=approver_name,
                        shift=shift,
                        approved_ips=added_ips,
                    )

                    success, email_message = send_approval_email(
                        smtp_host="",
                        smtp_port=0,
                        smtp_username="",
                        smtp_password="",
                        smtp_use_tls=True,
                        email_from=sender_email,
                        email_to=[receiver_email],
                        monitoring_emails=monitoring_list,
                        subject=subject,
                        html_body=html_body,
                        provider="gmail_api",
                        gmail_credentials_file=CONFIG.gmail_credentials_file,
                        gmail_token_file=CONFIG.gmail_token_file,
                        gmail_user_id=CONFIG.gmail_user_id,
                    )

                    if success:
                        st.success(f"✅ Added {len(added_ips)} IP(s) to master sheet and sent approval email!")
                        st.info(email_message)
                    else:
                        st.warning(f"⚠️ Added {len(added_ips)} IP(s) to master sheet but email failed: {email_message}")
                
                if failed_ips:
                    st.warning(f"❌ Failed to add these IPs (already exist?): {', '.join(failed_ips)}")
                
                st.rerun()

        with col2:
            if st.button("🧹 Clear Approved List", key="btn_clear_approved"):
                confirm_clear_approved_dialog()
        
        with col3:
            st.caption("Adds ALL approved IPs to Master Blocking Sheet and sends a single email with all approved IPs in one table.")
    else:
        st.info("No approved IPs yet. Mark IPs as 'Approved' above and they will appear here for bulk processing.")


def render_tab_master_sheet() -> None:
    """Tab 3: Display and edit master blocked sheet."""

    st.subheader("Master Blocking Sheet")
    st.caption(f"Source: {CONFIG.master_sheet_path}")

    rows = read_master_sheet_rows(Path(CONFIG.master_sheet_path))

    if not rows:
        st.info("Master sheet is empty or not found.")
        return

    normalized_rows: list[list[str]] = []
    for row in rows:
        adjusted = (row + ["", "", "", ""])[:10]
        normalized_rows.append(adjusted)

    df = pd.DataFrame(
        normalized_rows,
        columns=[
            "FALSE",
            "Date",
            "Shift Member Name",
            "Blocked IP Address",
            "Reason for Blocking",
            "Time of Blocking",
            "Approval Status",
            "Remarks/Additional Notes",
            "Abusive Percentage(AbuseIPDB)",
            "Status(Blocked / Pending)",
        ],
    )
    selection_df = df.copy()
    selection_df.insert(0, "Select", False)

    edited_master_df = st.data_editor(
        selection_df,
        width="stretch",
        hide_index=True,
        disabled=[
            "FALSE",
            "Date",
            "Shift Member Name",
            "Blocked IP Address",
            "Reason for Blocking",
            "Time of Blocking",
            "Approval Status",
            "Remarks/Additional Notes",
            "Abusive Percentage(AbuseIPDB)",
            "Status(Blocked / Pending)",
        ],
        column_config={
            "Select": st.column_config.CheckboxColumn(
                "Select",
                help="Select IPs for bulk update/delete",
                default=False,
            )
        },
        key="master_sheet_selector_table",
    )

    st.divider()
    st.markdown("### Edit or Delete Entries")
    selected_ips = [
        str(ip).strip()
        for ip in edited_master_df.loc[edited_master_df["Select"] == True, "Blocked IP Address"].tolist()
        if str(ip).strip()
        and str(ip).strip() not in {"Blocked IP Address", "[IP Address]"}
    ]

    st.caption("Use the Select column in the table above to choose one or more IPs.")

    action_type = st.radio(
        "Action",
        options=["Update Selected", "Delete Selected"],
        horizontal=True,
        key="bulk_action_type",
    )

    if selected_ips:
        st.info(f"{len(selected_ips)} IP(s) selected.")

    @st.dialog("Confirm Bulk Action")
    def bulk_action_dialog() -> None:
        selected_list = st.session_state.get("pending_selected_ips", [])
        pending_action = st.session_state.get("pending_bulk_action", "")

        if not selected_list:
            st.warning("No IPs selected.")
            return

        st.write(f"Action: **{pending_action}**")
        st.write(f"Selected IP count: **{len(selected_list)}**")

        if pending_action == "Update Selected":
            update_name = st.text_input("Approver Name", value="SOC Analyst", key="bulk_update_name")
            update_reason = st.text_input("Reason", value="Malicious Activity", key="bulk_update_reason")
            update_notes = st.text_area("Notes", value="Updated by SOC", key="bulk_update_notes", height=120)

            c1, c2 = st.columns(2)
            with c1:
                if st.button("✅ Confirm Update", key="confirm_bulk_update"):
                    success_count = 0
                    for ip_addr in selected_list:
                        if update_master_sheet_row(
                            Path(CONFIG.master_sheet_path),
                            ip_address=ip_addr,
                            name=update_name,
                            reason=update_reason,
                            notes=update_notes,
                        ):
                            success_count += 1
                    st.success(f"Updated {success_count}/{len(selected_list)} IP(s).")
                    st.session_state.pop("pending_selected_ips", None)
                    st.session_state.pop("pending_bulk_action", None)
                    st.rerun()
            with c2:
                st.button("Cancel", key="cancel_bulk_update")

        else:
            st.warning("This will permanently delete the selected entries from the master sheet.")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("🗑️ Confirm Delete", key="confirm_bulk_delete"):
                    success_count = 0
                    for ip_addr in selected_list:
                        if delete_master_sheet_row(Path(CONFIG.master_sheet_path), ip_addr):
                            success_count += 1
                    st.success(f"Deleted {success_count}/{len(selected_list)} IP(s).")
                    st.session_state.pop("pending_selected_ips", None)
                    st.session_state.pop("pending_bulk_action", None)
                    st.rerun()
            with c2:
                st.button("Cancel", key="cancel_bulk_delete")

    if st.button("Proceed", key="bulk_proceed", type="primary"):
        if not selected_ips:
            st.warning("Select at least one IP to continue.")
        else:
            st.session_state["pending_selected_ips"] = selected_ips
            st.session_state["pending_bulk_action"] = action_type
            bulk_action_dialog()


def render_tab_whitelist() -> None:
    """Tab 4: Display whitelisted IPs and CIDR blocks."""

    st.subheader("Whitelisted IPs & CIDR Blocks")
    st.caption(f"File source: {CONFIG.whitelist_sheet_path}")
    st.info("These IPs and CIDR blocks will NOT be sent to detected threats, preventing accidental blocking of trusted services.")

    individual_ips, cidr_blocks = load_whitelist_entries(CONFIG.whitelist_sheet_path)
    custom_entries = fetch_custom_whitelist_entries(CONFIG.sqlite_path)
    custom_ips = {entry["entry"] for entry in custom_entries if entry.get("entry_type") == "IP"}
    custom_cidrs = {entry["entry"] for entry in custom_entries if entry.get("entry_type") == "CIDR"}
    effective_ips = individual_ips | custom_ips
    effective_cidrs = cidr_blocks | custom_cidrs

    st.markdown("### Custom Whitelist Table")
    input_col, action_col, remove_col = st.columns([4, 1, 4])
    with input_col:
        custom_whitelist_input = st.text_input(
            "Add Custom IP or CIDR",
            placeholder="Examples: 192.168.1.10 or 10.0.0.0/24",
            key="custom_whitelist_input",
        )
    with action_col:
        st.write("")
        st.write("")
        if st.button("Add", key="btn_add_custom_whitelist", type="primary"):
            classified = classify_whitelist_entry(custom_whitelist_input)
            if not classified:
                st.error("Invalid value. Enter a valid IP address or CIDR block.")
            else:
                normalized_entry, entry_type = classified
                upsert_custom_whitelist_entry(CONFIG.sqlite_path, normalized_entry, entry_type)
                st.success(f"Added custom whitelist {entry_type}: {normalized_entry}")
                st.rerun()
    with remove_col:
        custom_whitelist_remove_input = st.text_input(
            "Remove Custom IP or CIDR",
            placeholder="Enter exact value to remove",
            key="custom_whitelist_remove_input",
        )
        if st.button("Remove", key="btn_remove_custom_whitelist"):
            target = custom_whitelist_remove_input.strip()
            if not target:
                st.warning("Enter an IP/CIDR value to remove.")
            elif delete_custom_whitelist_entry(CONFIG.sqlite_path, target):
                st.success(f"Removed custom whitelist entry: {target}")
                st.rerun()
            else:
                st.warning(f"No custom whitelist entry found for: {target}")

    if custom_entries:
        custom_df = pd.DataFrame(custom_entries)
        custom_df.insert(0, "Select", False)
        edited_custom_df = st.data_editor(
            custom_df[["Select", "entry", "entry_type", "created_at"]],
            width="stretch",
            hide_index=True,
            disabled=["entry", "entry_type", "created_at"],
            column_config={
                "Select": st.column_config.CheckboxColumn("Select", help="Select custom entries to delete", default=False),
                "entry": st.column_config.TextColumn("Entry", width="large"),
                "entry_type": st.column_config.TextColumn("Type", width="small"),
                "created_at": st.column_config.TextColumn("Created At", width="medium"),
            },
            key="custom_whitelist_editor",
        )

        selected_custom_entries = [
            str(entry).strip()
            for entry in edited_custom_df.loc[edited_custom_df["Select"] == True, "entry"].tolist()
            if str(entry).strip()
        ]
        if selected_custom_entries:
            if st.button("Delete Selected Custom Entries", key="btn_delete_custom_whitelist"):
                deleted_count = 0
                for entry in selected_custom_entries:
                    if delete_custom_whitelist_entry(CONFIG.sqlite_path, entry):
                        deleted_count += 1
                st.success(f"Deleted {deleted_count} custom whitelist entrie(s).")
                st.rerun()
    else:
        st.caption("No custom whitelist entries yet.")

    if not effective_ips and not effective_cidrs:
        st.warning("No whitelisted entries found. Check the whitelist file path.")
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Individual Whitelisted IPs")
        if effective_ips:
            st.info(f"**Total: {len(effective_ips)} IPs** (file: {len(individual_ips)}, custom: {len(custom_ips)})")
            with st.expander("View all whitelisted IPs", expanded=False):
                ips_list = sorted(list(effective_ips))
                st.code("\n".join(ips_list), language="text")
        else:
            st.write("No individual IPs in whitelist.")

    with col2:
        st.markdown("### Whitelisted CIDR Blocks")
        if effective_cidrs:
            st.info(f"**Total: {len(effective_cidrs)} CIDR blocks** (file: {len(cidr_blocks)}, custom: {len(custom_cidrs)})")
            with st.expander("View all whitelisted CIDR blocks", expanded=False):
                cidrs_list = sorted(list(effective_cidrs))
                st.code("\n".join(cidrs_list), language="text")
        else:
            st.write("No CIDR blocks in whitelist.")

    st.divider()
    st.markdown("### Summary")
    summary_col1, summary_col2, summary_col3 = st.columns(3)
    with summary_col1:
        st.metric("Individual IPs", len(effective_ips))
    with summary_col2:
        st.metric("CIDR Blocks", len(effective_cidrs))
    with summary_col3:
        st.metric("Custom Entries", len(custom_entries))


def analyze_logpush_sample(log_file_path: Path, max_lines: int = 10000) -> dict:
    """Analyze a sample of logpush data and return detection statistics."""
    if not log_file_path.exists():
        return {}
    
    ip_requests = defaultdict(list)
    sensitive_paths = {"/wp-login.php", "/admin", "/login", "/.env"}
    
    try:
        with log_file_path.open("r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if idx >= max_lines:
                    break
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    ip = entry.get("ClientIP", "")
                    uri = entry.get("ClientRequestURI", "/")
                    if ip:
                        ip_requests[ip].append(uri)
                except:
                    continue
        
        high_volume_ips = {ip: len(paths) for ip, paths in ip_requests.items() if len(paths) > 20}
        scanner_ips = {ip: len(set(paths)) for ip, paths in ip_requests.items() if len(set(paths)) > 10}
        sensitive_ips = {
            ip: sum(1 for p in paths if p in sensitive_paths)
            for ip, paths in ip_requests.items()
            if sum(1 for p in paths if p in sensitive_paths) > 5
        }
        
        return {
            "total_ips": len(ip_requests),
            "total_requests": sum(len(paths) for paths in ip_requests.values()),
            "lines_analyzed": min(idx + 1, max_lines),
            "high_volume_count": len(high_volume_ips),
            "scanner_count": len(scanner_ips),
            "sensitive_abuse_count": len(sensitive_ips),
            "high_volume_ips": list(high_volume_ips.items())[:5],
            "scanner_ips": list(scanner_ips.items())[:5],
            "sensitive_ips": list(sensitive_ips.items())[:5],
        }
    except Exception:
        return {}


def render_tab_cloudflare_soar() -> None:
    """Tab 5: Cloudflare Logpush SOAR module details and controls."""

    st.subheader("Cloudflare Logpush SOAR Module")
    st.caption("Continuous interval-based IP scanning and automatic Cloudflare blocking.")

    project_root = Path(__file__).parent.parent
    soar_script_path = Path(__file__).parent / "cloudflare_soar_module.py"
    decision_log_path = project_root / "soar_decisions.log"
    state_file_path = project_root / "blocked_state.json"
    logpush_sample_path = project_root / "logpush_simulation.json"
    running = is_soar_running()

    st.markdown("### Module Status")
    status_col1, status_col2, status_col3 = st.columns(3)
    with status_col1:
        st.metric("SOAR Script", "Available" if soar_script_path.exists() else "Missing")
    with status_col2:
        st.metric("Decision Log", "Found" if decision_log_path.exists() else "Not Found")
    with status_col3:
        st.metric("Blocked State", "Found" if state_file_path.exists() else "Not Found")

    run_col1, run_col2, run_col3 = st.columns([2, 2, 4])
    with run_col1:
        st.metric("Runtime", "Running" if running else "Stopped")
    with run_col2:
        if st.button("▶ Start SOAR", key="btn_start_soar", disabled=running):
            ok, message = start_soar_module_process()
            if ok:
                st.success(message)
            else:
                st.warning(message)
            st.rerun()
    with run_col3:
        if st.button("■ Stop SOAR", key="btn_stop_soar", disabled=not running):
            ok, message = stop_soar_module_process()
            if ok:
                st.success(message)
            else:
                st.warning(message)
            st.rerun()

    st.markdown("### Logpush Data Source")
    if logpush_sample_path.exists():
        st.success(f"📄 Logpush simulation file found: `{logpush_sample_path.name}`")
        st.caption(f"Full path: {logpush_sample_path}")
    else:
        st.warning("No logpush_simulation.json found in workspace root.")
    
    st.markdown("### Detection Rules")
    rule_col1, rule_col2 = st.columns(2)
    with rule_col1:
        st.write("**High Volume (>20 requests/60s)**")
        st.caption("Flags IPs making excessive requests")
        st.write("**Sensitive Path Abuse (>5 hits/60s)**")
        st.caption("/wp-login.php, /admin, /login, /.env")
    with rule_col2:
        st.write("**Scanner Behavior (>10 unique paths/60s)**")
        st.caption("Detects path enumeration/scanning")
        st.write("**Auto-unblock after 24 hours**")
        st.caption("Configurable via AUTO_UNBLOCK_HOURS")

    st.markdown("### Log Analysis Preview")
    if logpush_sample_path.exists():
        analysis_size = st.slider(
            "Analysis Sample Size",
            min_value=1000,
            max_value=50000,
            value=10000,
            step=1000,
            help="Number of log lines to analyze (larger = more accurate but slower)",
        )
        with st.spinner(f"Analyzing {analysis_size:,} log entries..."):
            stats = analyze_logpush_sample(logpush_sample_path, max_lines=analysis_size)
        
        if stats:
            st.caption(f"Analyzed {stats.get('lines_analyzed', 0):,} log lines")
            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            with metric_col1:
                st.metric("Unique IPs", stats.get("total_ips", 0))
            with metric_col2:
                st.metric("Total Requests", stats.get("total_requests", 0))
            with metric_col3:
                st.metric("High Volume IPs", stats.get("high_volume_count", 0))
            with metric_col4:
                st.metric("Scanner IPs", stats.get("scanner_count", 0))
            
            threat_count = stats.get('high_volume_count', 0) + stats.get('scanner_count', 0) + stats.get('sensitive_abuse_count', 0)
            if threat_count > 0:
                st.warning(f"🚨 {threat_count} total IP(s) would be blocked by SOAR module")
            else:
                st.info("✅ No threats detected in sample. IPs may be distributed (1 request each) or increase sample size.")
            
            if stats.get("sensitive_ips"):
                with st.expander(f"🔴 Sensitive Path Abusers ({stats.get('sensitive_abuse_count', 0)} IPs)", expanded=True):
                    for ip, count in stats.get("sensitive_ips", []):
                        st.code(f"{ip}: {count} sensitive path hits")
            
            if stats.get("high_volume_ips"):
                with st.expander(f"⚠️ High Volume IPs ({stats.get('high_volume_count', 0)} IPs)"):
                    for ip, count in stats.get("high_volume_ips", []):
                        st.code(f"{ip}: {count} requests")
            
            if stats.get("scanner_ips"):
                with st.expander(f"🔍 Scanner IPs ({stats.get('scanner_count', 0)} IPs)"):
                    for ip, count in stats.get("scanner_ips", []):
                        st.code(f"{ip}: {count} unique paths scanned")
    else:
        st.info("Upload logpush_simulation.json to workspace root for analysis preview.")

    st.markdown("### Environment Variables")
    env_col1, env_col2 = st.columns(2)
    with env_col1:
        token_set = bool(os.getenv("CLOUDFLARE_API_TOKEN", "").strip())
        zone_set = bool(os.getenv("ZONE_ID", "").strip())
        demo_mode = os.getenv("DEMO_MODE", "").strip().lower() in ("1", "true", "yes")
        st.metric("CLOUDFLARE_API_TOKEN", "Set" if token_set else "Missing")
        st.metric("ZONE_ID", "Set" if zone_set else "Missing")
        st.metric("DEMO_MODE", "Enabled" if demo_mode else "Disabled")
        if demo_mode:
            st.info("ℹ️ Demo mode: detections are logged but no actual blocking occurs.")
    with env_col2:
        st.code(
            "\n".join(
                [
                    "# Demo mode (no API credentials needed)",
                    "export DEMO_MODE=1",
                    f"export LOG_INPUT_PATH='{logpush_sample_path}'",
                    "",
                    "# Production mode (requires credentials)",
                    "export CLOUDFLARE_API_TOKEN='your-token'",
                    "export ZONE_ID='your-zone-id'",
                    f"export LOG_INPUT_PATH='{logpush_sample_path}'",
                    "",
                    "# Start SOAR module",
                    "python soc_ip_governance/cloudflare_soar_module.py",
                ]
            ),
            language="bash",
        )

    st.markdown("### Recent Decisions")
    if decision_log_path.exists():
        try:
            log_lines = decision_log_path.read_text(encoding="utf-8").splitlines()
            preview = "\n".join(log_lines[-30:]) if log_lines else "No decisions logged yet."
            st.code(preview, language="text")
        except Exception as exc:
            st.warning(f"Unable to read decision log: {exc}")
    else:
        st.info("Run the SOAR script once to generate soar_decisions.log.")

    st.markdown("### Runtime Output")
    if SOAR_RUNTIME_LOG.exists():
        try:
            runtime_lines = SOAR_RUNTIME_LOG.read_text(encoding="utf-8").splitlines()
            runtime_preview = "\n".join(runtime_lines[-40:]) if runtime_lines else "No runtime output yet."
            st.code(runtime_preview, language="text")
        except Exception as exc:
            st.warning(f"Unable to read runtime log: {exc}")
    else:
        st.info("Runtime log will appear after starting the SOAR module.")


def main() -> None:
    """Application entry point."""

    st.set_page_config(
        page_title="SOC IP Governance Automation",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for professional Lentra-inspired theme
    st.markdown("""
        <style>
        /* Import Google Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        /* Global Theme */
        :root {
            --primary-blue: #2C5F7E;
            --accent-orange: #FF8C42;
            --dark-navy: #1E3A50;
            --light-blue: #E8F1F5;
            --text-dark: #2D3E50;
            --text-light: #6C7A89;
            --border-color: #D0D8E0;
            --success-green: #28A745;
            --warning-orange: #FF8C42;
            --danger-red: #DC3545;
        }
        
        /* Main Container */
        .main {
            background: linear-gradient(135deg, #F7F9FC 0%, #FFFFFF 100%);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        /* Headers */
        h1 {
            color: var(--primary-blue) !important;
            font-weight: 700 !important;
            font-size: 2.5rem !important;
            margin-bottom: 0.5rem !important;
            letter-spacing: -0.5px !important;
        }
        
        h2 {
            color: var(--dark-navy) !important;
            font-weight: 600 !important;
            font-size: 1.8rem !important;
            margin-top: 2rem !important;
            padding-bottom: 0.5rem !important;
            border-bottom: 3px solid var(--accent-orange) !important;
        }
        
        h3 {
            color: var(--primary-blue) !important;
            font-weight: 600 !important;
            font-size: 1.3rem !important;
        }
        
        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
            background: white;
            border-radius: 12px 12px 0 0;
            padding: 12px 12px 0 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            background: transparent;
            border-radius: 8px 8px 0 0;
            color: var(--text-light);
            font-weight: 500;
            font-size: 1rem;
            padding: 0 24px;
            transition: all 0.3s ease;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            background: var(--light-blue);
            color: var(--primary-blue);
        }
        
        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--dark-navy) 100%);
            color: white !important;
            font-weight: 600;
        }
        
        /* Tab Content */
        .stTabs [data-baseweb="tab-panel"] {
            background: white;
            padding: 2rem;
            border-radius: 0 12px 12px 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        
        /* Buttons */
        .stButton > button {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--dark-navy) 100%);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 0.6rem 1.5rem;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(44, 95, 126, 0.3);
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(44, 95, 126, 0.4);
        }
        
        button[kind="primary"] {
            background: linear-gradient(135deg, var(--accent-orange) 0%, #FF6B35 100%) !important;
        }
        
        button[kind="secondary"] {
            background: white !important;
            color: var(--primary-blue) !important;
            border: 2px solid var(--primary-blue) !important;
        }
        
        /* Text Input & Text Area */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea {
            border-radius: 8px;
            border: 2px solid var(--border-color);
            padding: 0.75rem;
            font-size: 0.95rem;
            transition: all 0.3s ease;
        }
        
        .stTextInput > div > div > input:focus,
        .stTextArea > div > div > textarea:focus {
            border-color: var(--primary-blue);
            box-shadow: 0 0 0 3px rgba(44, 95, 126, 0.1);
        }
        
        /* Data Frames & Tables */
        .dataframe {
            border: none !important;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .dataframe thead tr th {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--dark-navy) 100%) !important;
            color: white !important;
            font-weight: 600 !important;
            padding: 1rem !important;
            border: none !important;
        }
        
        .dataframe tbody tr:nth-child(even) {
            background: #F8FAFB;
        }
        
        .dataframe tbody tr:hover {
            background: var(--light-blue);
            transition: background 0.2s ease;
        }
        
        /* Metrics */
        [data-testid="stMetricValue"] {
            color: var(--primary-blue);
            font-size: 2rem;
            font-weight: 700;
        }
        
        [data-testid="stMetricLabel"] {
            color: var(--text-light);
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.85rem;
        }
        
        /* Info/Warning/Success/Error Boxes */
        .stAlert {
            border-radius: 8px;
            border: none;
            padding: 1rem 1.5rem;
            font-weight: 500;
        }
        
        div[data-baseweb="notification"] {
            border-radius: 8px;
        }
        
        /* Expanders */
        .streamlit-expanderHeader {
            background: white;
            font-weight: 600;
            color: var(--primary-blue);
            border-radius: 8px;
            border: 2px solid var(--border-color);
        }
        
        .streamlit-expanderHeader:hover {
            border-color: var(--primary-blue);
        }
        
        /* Sidebar */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, var(--dark-navy) 0%, var(--primary-blue) 100%);
        }
        
        [data-testid="stSidebar"] * {
            color: white !important;
        }
        
        /* Data Editor */
        [data-testid="stDataFrameResizable"] {
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        /* Progress Bar */
        .stProgress > div > div > div {
            background: linear-gradient(90deg, var(--accent-orange) 0%, #FF6B35 100%);
        }
        
        /* Columns Spacing */
        [data-testid="column"] {
            padding: 0.5rem;
        }
        
        /* Caption Styling */
        .caption {
            color: var(--text-light);
            font-size: 0.9rem;
            font-weight: 400;
        }
        
        /* Custom Card Style */
        .custom-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-left: 4px solid var(--accent-orange);
            margin: 1rem 0;
        }
        
        /* Number Input */
        .stNumberInput > div > div > input {
            border-radius: 8px;
            border: 2px solid var(--border-color);
        }
        
        /* Select Box */
        .stSelectbox > div > div {
            border-radius: 8px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Header with custom styling
    st.markdown("""
        <div style='text-align: left; padding: 1.5rem 0; border-bottom: 3px solid #FF8C42; margin-bottom: 1.5rem;'>
            <h1 style='margin: 0; color: #2C5F7E; font-size: 2.8rem;'>
                🛡️ SOC IP Governance Automation System
            </h1>
            <p style='color: #6C7A89; font-size: 1.1rem; margin-top: 0.5rem; font-weight: 500;'>
                Passive SOC Mode: Governance and Documentation
            </p>
        </div>
    """, unsafe_allow_html=True)

    authenticated_email = get_authenticated_email(CONFIG.gmail_token_file)

    if not authenticated_email:
        st.warning("Gmail authentication is required before accessing the dashboard.")
        st.info(
            "Click Authenticate with Gmail. After successful sign-in, the same Gmail ID will be used as sender email."
        )
        if st.button("Authenticate with Gmail", type="primary"):
            success, message, email = authenticate_gmail(
                credentials_file=CONFIG.gmail_credentials_file,
                token_file=CONFIG.gmail_token_file,
            )
            if success and email:
                st.session_state.authenticated_email = email
                st.success(message)
                st.rerun()
            else:
                st.error(message)
        st.stop()

    st.session_state.authenticated_email = authenticated_email

    header_col1, header_col2 = st.columns([8, 2])
    with header_col1:
        st.caption(f"Authenticated as: {authenticated_email}")
    with header_col2:
        if st.button("Logout Gmail"):
            clear_authentication(CONFIG.gmail_token_file)
            st.session_state.pop("authenticated_email", None)
            st.rerun()

    if not CONFIG.abuseipdb_api_key:
        st.warning(
            "AbuseIPDB API key missing. Set ABUSEIPDB_API_KEY or update soc_ip_governance/config.ini before processing."
        )

    if not Path(CONFIG.master_sheet_path).exists():
        st.warning(
            f"Master sheet file not found: {CONFIG.master_sheet_path}. "
            "Update [paths].master_sheet in config.ini or place the file at this location."
        )

    if not Path(CONFIG.whitelist_sheet_path).exists():
        st.warning(
            f"Whitelist file not found: {CONFIG.whitelist_sheet_path}. "
            "Update [paths].whitelist_sheet in config.ini or place the file at this location."
        )

    sqlite_parent = Path(CONFIG.sqlite_path).parent
    if not sqlite_parent.exists():
        st.error(
            f"SQLite directory does not exist: {sqlite_parent}. "
            "Create this folder or update [paths].sqlite_db in config.ini."
        )
    elif not sqlite_parent.is_dir():
        st.error(
            f"SQLite parent path is not a directory: {sqlite_parent}. "
            "Fix [paths].sqlite_db in config.ini."
        )

    initialize_state()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Raw Input Processing",
        "Detected Threats",
        "Master Blocking Sheet",
        "Whitelisted IPs",
        "Cloudflare SOAR",
    ])

    with tab1:
        render_tab_raw_input()
    with tab2:
        render_tab_detected_threats()
    with tab3:
        render_tab_master_sheet()
    with tab4:
        render_tab_whitelist()
    with tab5:
        render_tab_cloudflare_soar()


if __name__ == "__main__":
    main()
