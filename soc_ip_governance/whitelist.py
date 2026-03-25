"""Whitelist management for IP governance - prevents blocking of trusted IPs."""

from __future__ import annotations

import csv
import logging
from ipaddress import ip_address, ip_network, AddressValueError
from pathlib import Path

logger = logging.getLogger(__name__)


def classify_whitelist_entry(value: str) -> tuple[str, str] | None:
    """Validate and normalize one whitelist value into (entry, entry_type)."""

    text = value.strip()
    if not text:
        return None

    try:
        if "/" in text:
            network_obj = ip_network(text, strict=False)
            return str(network_obj), "CIDR"

        ip_obj = ip_address(text)
        return str(ip_obj), "IP"
    except (AddressValueError, ValueError):
        return None


def load_whitelist_entries(whitelist_csv_path: Path) -> tuple[set[str], set[str]]:
    """
    Load whitelisted IPs and CIDR blocks from CSV file.
    
    Args:
        whitelist_csv_path: Path to whitelist CSV (e.g., ip_not_blocked.csv)
        
    Returns:
        Tuple of (individual_ips set, cidr_blocks set)
    """
    individual_ips: set[str] = set()
    cidr_blocks: set[str] = set()
    
    if not whitelist_csv_path.exists():
        logger.warning("Whitelist CSV does not exist: %s", whitelist_csv_path)
        return individual_ips, cidr_blocks
    
    try:
        with whitelist_csv_path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                # Iterate through all cells in each row
                for cell in row:
                    value = cell.strip()
                    if not value:
                        continue
                    
                    # Skip header-like entries
                    if any(keyword in value.lower() for keyword in ["region", "whitelisted", "proxy", "crawler", "range", "ip", "address", "office"]):
                        continue
                    
                    # Check if it's a CIDR block (contains /)
                    if "/" in value:
                        try:
                            # Validate CIDR block
                            ip_network(value)
                            cidr_blocks.add(value)
                            logger.debug("Added CIDR block to whitelist: %s", value)
                        except (AddressValueError, ValueError):
                            logger.debug("Invalid CIDR block format: %s", value)
                    else:
                        # Try to parse as IP address (IPv4 or IPv6)
                        try:
                            ip_address(value)
                            individual_ips.add(value)
                            logger.debug("Added IP to whitelist: %s", value)
                        except (AddressValueError, ValueError):
                            # May be a partial IP pattern like "172.30*" - skip for now
                            pass
    
    except Exception as e:
        logger.exception("Failed to load whitelist from %s: %s", whitelist_csv_path, e)
    
    logger.info("Loaded whitelist: %d individual IPs, %d CIDR blocks", len(individual_ips), len(cidr_blocks))
    return individual_ips, cidr_blocks


def is_ip_whitelisted(ip_addr: str, individual_ips: set[str], cidr_blocks: set[str]) -> bool:
    """
    Check if an IP is whitelisted (exact match or within CIDR block).
    
    Args:
        ip_addr: IP address to check (string)
        individual_ips: Set of individual whitelisted IPs
        cidr_blocks: Set of whitelisted CIDR blocks
        
    Returns:
        True if IP is whitelisted, False otherwise
    """
    # Check exact match
    if ip_addr in individual_ips:
        return True
    
    # Check if IP is within any CIDR block
    try:
        ip_obj = ip_address(ip_addr)
        for cidr in cidr_blocks:
            try:
                network_obj = ip_network(cidr)
                if ip_obj in network_obj:
                    return True
            except (AddressValueError, ValueError):
                pass
    except (AddressValueError, ValueError):
        # Invalid IP format
        pass
    
    return False


def filter_whitelisted_ips(
    ip_list: list[str], 
    individual_ips: set[str], 
    cidr_blocks: set[str]
) -> tuple[list[str], list[str], int]:
    """
    Filter out whitelisted IPs from a list.
    
    Args:
        ip_list: List of IPs to filter
        individual_ips: Set of individual whitelisted IPs
        cidr_blocks: Set of whitelisted CIDR blocks
        
    Returns:
        Tuple of (filtered_ips, whitelisted_ips, whitelisted_count)
    """
    filtered_ips: list[str] = []
    whitelisted_ips: list[str] = []
    
    for ip_addr in ip_list:
        if is_ip_whitelisted(ip_addr, individual_ips, cidr_blocks):
            whitelisted_ips.append(ip_addr)
        else:
            filtered_ips.append(ip_addr)
    
    return filtered_ips, whitelisted_ips, len(whitelisted_ips)
