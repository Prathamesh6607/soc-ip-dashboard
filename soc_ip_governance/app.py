"""Streamlit SOC IP Governance Automation dashboard."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from abuseipdb import query_abuseipdb
from config import CONFIG
from database import (
    fetch_scan_results,
    fetch_detected_threats,
    init_database,
    update_approval_status,
    upsert_scan_result,
    upsert_detected_threat,
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
    load_whitelist_entries,
    filter_whitelisted_ips,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)


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


def process_raw_input(raw_text: str, threshold: int) -> None:
    """Run full passive SOC processing pipeline for multiline input."""

    valid_ips, invalid_entries, total_lines = extract_valid_ips(raw_text)
    unique_valid_ips, duplicate_count = remove_duplicates(valid_ips)

    # Load and apply whitelist filtering
    individual_ips, cidr_blocks = load_whitelist_entries(CONFIG.whitelist_sheet_path)
    non_whitelisted_ips, whitelisted_ips, whitelist_count = filter_whitelisted_ips(
        unique_valid_ips, individual_ips, cidr_blocks
    )

    blocked_ips = load_master_blocked_ips(CONFIG.master_sheet_path)
    new_ips, already_blocked_count = filter_already_blocked(non_whitelisted_ips, blocked_ips)

    detected_threats: list[dict] = []
    api_failed_checks = 0
    for ip_addr in new_ips:
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
        process_raw_input(raw_text=raw_text, threshold=int(threshold))
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

    min_abuse_score = st.slider(
        "Minimum Abuse Confidence Score to Display",
        min_value=0,
        max_value=100,
        value=20,
        step=1,
        help="Show only IPs with abuse score >= this value",
    )

    scanned_results = fetch_scan_results(CONFIG.sqlite_path, min_score=min_abuse_score)
    if scanned_results:
        st.markdown(f"### AbuseIPDB Scanned Results (Abuse Score ≥ {min_abuse_score})")
        
        col1, col2 = st.columns([10, 2])
        col1.write("")
        clear_btn = col2.button("🗑️ Clear All Results", key="clear_all_results")
        
        if clear_btn:
            deleted_count = clear_all_scan_results(CONFIG.sqlite_path)
            st.success(f"Cleared {deleted_count} scan results.")
            st.rerun()
        
        scanned_df = pd.DataFrame(scanned_results)
        st.dataframe(
            scanned_df[["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH"]],
            width="stretch",
            hide_index=True,
        )
        
        st.markdown("### Edit PATH Column")
        for result in scanned_results:
            ip_addr = result["ipAddress"]
            current_path = result["PATH"]
            score = result["abuseConfidenceScore"]
            
            col1, col2 = st.columns([3, 2])
            with col1:
                new_path = st.text_input(
                    f"PATH for {ip_addr} (Score: {score})",
                    value=current_path,
                    key=f"path_input_{ip_addr}",
                    label_visibility="collapsed",
                )
            with col2:
                if st.button("Update PATH", key=f"update_path_{ip_addr}"):
                    update_scan_result_path(CONFIG.sqlite_path, ip_addr, new_path)
                    st.success(f"Updated PATH for {ip_addr}")
                    st.rerun()
    else:
        st.info(f"No scan results with abuse score >= {min_abuse_score}. Process IPs in Tab 1 first.")
        return

    threats = fetch_detected_threats(CONFIG.sqlite_path)
    if not threats:
        st.info("No detected threats above the selected threshold yet.")
        return

    st.markdown("### Detected Threats (Above Threshold)")

    df = pd.DataFrame(threats)
    st.dataframe(
        df[["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH"]],
        width="stretch",
        hide_index=True,
    )

    st.divider()
    st.markdown("### Approval Actions")

    sender_email = st.session_state.get("authenticated_email", "")
    receiver_email = CONFIG.approval_receiver_email
    monitoring_list = parse_email_list(CONFIG.monitoring_emails)

    if sender_email:
        st.caption(f"Authenticated sender: {sender_email} | Receiver: {receiver_email}")

    col1, col2, col3 = st.columns(3)
    with col1:
        approver_name = st.selectbox(
            "Approver Name",
            ["Priyanka Maam", "Pankaj Sir"],
            index=0,
        )
    with col2:
        shift = st.selectbox(
            "Shift",
            ["Morning", "Afternoon", "Night"],
            index=0,
        )
    with col3:
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
    st.caption("Mark IPs as Approved or Rejected, then use the bulk action button below to add all approved IPs at once.")
    
    for row in threats:
        ip_addr = row["ipAddress"]
        c1, c2, c3 = st.columns([3, 2, 2])
        c1.write(f"{ip_addr} (Score: {row['abuseConfidenceScore']})")

        status_key = f"status_{ip_addr}"
        selected_status = c2.selectbox(
            "Approval Status",
            ["Pending", "Approved", "Rejected"],
            index=["Pending", "Approved", "Rejected"].index(row.get("Approval Status", "Pending")),
            key=status_key,
            label_visibility="collapsed",
        )

        if c3.button("Update Status", key=f"update_{ip_addr}"):
            update_approval_status(CONFIG.sqlite_path, ip_addr, selected_status)
            st.success(f"Updated status for {ip_addr} to {selected_status}")
            st.rerun()

    st.divider()
    st.markdown("### Bulk Action: Add All Approved IPs to Master Block List")
    
    # Fetch all approved threats
    all_threats = fetch_detected_threats(CONFIG.sqlite_path)
    approved_threats = [t for t in all_threats if t.get("Approval Status") == "Approved"]
    
    if approved_threats:
        st.info(f"**{len(approved_threats)} IP(s) ready to be added to Master Blocking Sheet and notified via email.**")
        
        # Display approved IPs summary
        with st.expander("View Approved IPs to be Added", expanded=True):
            approved_df = pd.DataFrame(approved_threats)
            st.dataframe(
                approved_df[["ipAddress", "abuseConfidenceScore", "countryCode", "isp", "PATH"]],
                width="stretch",
                hide_index=True,
            )
        
        # Bulk approval button
        col1, col2 = st.columns([2, 4])
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
                        name=approver_name,
                        ip_address=ip_addr,
                        notes=default_notes,
                        shift=shift,
                        reason=CONFIG.default_reason,
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
        adjusted = (row + ["", "", ""])[:9]
        normalized_rows.append(adjusted)

    df = pd.DataFrame(
        normalized_rows,
        columns=[
            "YYYY-MM-DD",
            "Name",
            "IP Address",
            "Reason",
            "HH:MM AM/PM",
            "",
            "Notes",
            " ",
            "  ",
        ],
    )
    st.dataframe(df, width="stretch", hide_index=True)

    st.divider()
    st.markdown("### Edit or Delete Entries")

    col1, col2 = st.columns([2, 4])

    with col1:
        ip_to_modify = st.selectbox(
            "Select IP to Edit/Delete",
            [row[2].strip() for row in rows if len(row) > 2],
            key="ip_selector",
        )

    # Find the row data for selected IP
    selected_row = None
    for row in rows:
        if len(row) > 2 and row[2].strip() == ip_to_modify:
            selected_row = row
            break

    if selected_row:
        st.markdown(f"**Editing IP: {ip_to_modify}**")

        col1, col2 = st.columns(2)
        with col1:
            new_name = st.text_input(
                "Approver Name",
                value=selected_row[1] if len(selected_row) > 1 else "SOC Analyst",
                key="edit_name",
            )
            new_reason = st.text_input(
                "Reason",
                value=selected_row[3] if len(selected_row) > 3 else "Malicious Activity",
                key="edit_reason",
            )

        with col2:
            new_notes = st.text_area(
                "Notes",
                value=selected_row[6] if len(selected_row) > 6 else "No notes",
                height=120,
                key="edit_notes",
            )

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("✅ Update Entry", key="btn_update_entry"):
                success = update_master_sheet_row(
                    Path(CONFIG.master_sheet_path),
                    ip_address=ip_to_modify,
                    name=new_name,
                    reason=new_reason,
                    notes=new_notes,
                )
                if success:
                    st.success(f"Updated {ip_to_modify} successfully!")
                    st.rerun()
                else:
                    st.error(f"Failed to update {ip_to_modify}")

        with col2:
            if st.button("🗑️ Delete Entry", key="btn_delete_entry"):
                success = delete_master_sheet_row(Path(CONFIG.master_sheet_path), ip_to_modify)
                if success:
                    st.success(f"Deleted {ip_to_modify} successfully!")
                    st.rerun()
                else:
                    st.error(f"Failed to delete {ip_to_modify}")


def render_tab_whitelist() -> None:
    """Tab 4: Display whitelisted IPs and CIDR blocks."""

    st.subheader("Whitelisted IPs & CIDR Blocks")
    st.caption(f"Source: {CONFIG.whitelist_sheet_path}")
    st.info("These IPs and CIDR blocks will NOT be sent to detected threats, preventing accidental blocking of trusted services.")

    individual_ips, cidr_blocks = load_whitelist_entries(CONFIG.whitelist_sheet_path)

    if not individual_ips and not cidr_blocks:
        st.warning("No whitelisted entries found. Check the whitelist file path.")
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Individual Whitelisted IPs")
        if individual_ips:
            st.info(f"**Total: {len(individual_ips)} IPs**")
            with st.expander("View all whitelisted IPs", expanded=False):
                ips_list = sorted(list(individual_ips))
                st.code("\n".join(ips_list), language="text")
        else:
            st.write("No individual IPs in whitelist.")

    with col2:
        st.markdown("### Whitelisted CIDR Blocks")
        if cidr_blocks:
            st.info(f"**Total: {len(cidr_blocks)} CIDR blocks**")
            with st.expander("View all whitelisted CIDR blocks", expanded=False):
                cidrs_list = sorted(list(cidr_blocks))
                st.code("\n".join(cidrs_list), language="text")
        else:
            st.write("No CIDR blocks in whitelist.")

    st.divider()
    st.markdown("### Summary")
    summary_col1, summary_col2 = st.columns(2)
    with summary_col1:
        st.metric("Individual IPs", len(individual_ips))
    with summary_col2:
        st.metric("CIDR Blocks", len(cidr_blocks))


def main() -> None:
    """Application entry point."""

    st.set_page_config(page_title="SOC IP Governance Automation", layout="wide")
    st.title("SOC IP Governance Automation System")
    st.caption("Passive SOC mode: governance and documentation only")

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

    initialize_state()

    tab1, tab2, tab3, tab4 = st.tabs(["Raw Input Processing", "Detected Threats", "Master Blocking Sheet", "Whitelisted IPs"])

    with tab1:
        render_tab_raw_input()
    with tab2:
        render_tab_detected_threats()
    with tab3:
        render_tab_master_sheet()
    with tab4:
        render_tab_whitelist()


if __name__ == "__main__":
    main()
