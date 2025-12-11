#!/usr/bin/env python3
"""
Cloudflare Security Events Monitor

Fetch and analyze Cloudflare firewall security events via GraphQL API.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import requests


# Constants
CLOUDFLARE_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"

ABUSEIPDB_CATEGORIES = "15,21"  # 15=Hacking, 21=Web App Attack
ABUSEIPDB_MAX_AGE_DAYS = 90
ABUSEIPDB_COMMENT_MAX_LENGTH = 1024

DEFAULT_LOOKBACK_MINUTES = 1440  # 24 hours
DEFAULT_EVENT_LIMIT = 1000
REQUEST_TIMEOUT = 15

TABLE_BORDER_CHARS = {
    "horizontal": "─",
    "vertical": "│",
    "top_left": "┌",
    "top_right": "┐",
    "bottom_left": "└",
    "bottom_right": "┘",
    "cross": "┼",
    "t_down": "┬",
    "t_up": "┴",
    "t_right": "├",
    "t_left": "┤",
}

# ANSI color codes
COLOR_GREEN = "\033[32m"
COLOR_ORANGE = "\033[33m"
COLOR_RED = "\033[31m"
COLOR_RESET = "\033[0m"


@dataclass
class AbuseIPInfo:
    """IP abuse information from AbuseIPDB."""
    country: str
    isp: str
    abuse_score: int


@dataclass
class CloudflareEvent:
    """Cloudflare firewall event."""
    datetime: str
    client_ip: str
    action: str
    source: str
    user_agent: str
    country: str
    rule_id: str
    ray_name: str
    http_host: str
    http_method: str
    path: str


# ============================================================================
# AbuseIPDB API Functions
# ============================================================================

def check_ip_reputation(ip: str, api_key: str) -> Optional[AbuseIPInfo]:
    """
    Check IP reputation using AbuseIPDB API.
    
    Args:
        ip: IP address to check
        api_key: AbuseIPDB API key
        
    Returns:
        AbuseIPInfo object or None on error
    """
    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            params={"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            return None
            
        data = response.json().get("data")
        if not data:
            return None
            
        return AbuseIPInfo(
            country=data.get("countryName", "N/A"),
            isp=data.get("isp", "N/A"),
            abuse_score=data.get("abuseConfidenceScore", 0)
        )
    except Exception:
        return None


def report_ip_to_abuseipdb(ip: str, api_key: str, comment: str, timestamp: Optional[str] = None) -> bool:
    """
    Report an IP to AbuseIPDB API.
    
    Args:
        ip: IP address to report
        api_key: AbuseIPDB API key
        comment: Comment describing the abuse
        timestamp: Optional ISO 8601 timestamp
        
    Returns:
        True if successful, False otherwise
    """
    try:
        data = {
            "ip": ip,
            "categories": ABUSEIPDB_CATEGORIES,
            "comment": comment[:ABUSEIPDB_COMMENT_MAX_LENGTH]
        }
        
        if timestamp:
            data["timestamp"] = timestamp
        
        response = requests.post(
            ABUSEIPDB_REPORT_URL,
            data=data,
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            print(f"  ⚠️  Failed to report {ip}: {response.status_code}")
            return False
            
        return True
    except Exception as e:
        print(f"  ⚠️  Error reporting {ip}: {e}")
        return False


# ============================================================================
# Cloudflare GraphQL Functions
# ============================================================================

def get_graphql_headers(api_token: str) -> Dict[str, str]:
    """Build headers for Cloudflare GraphQL requests."""
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }


def get_default_firewall_query() -> str:
    """Get default GraphQL query for firewall events."""
    return '''query FirewallEvents($zoneTag: string, $limit: int, $since: Time, $until: Time) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(limit: $limit, filter: {datetime_geq: $since, datetime_leq: $until, source_neq: "hot"}) {
        datetime
        clientIP
        action
        source
        userAgent
        clientCountryName
        ruleId
        rayName
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestPath
        edgeResponseStatus
      }
    }
  }
}'''


def build_query_variables(zone_id: str, limit: int, minutes: int) -> Tuple[Dict, datetime, datetime]:
    """Build GraphQL query variables with time range."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes)
    
    variables = {
        "zoneTag": zone_id,
        "limit": limit,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": now.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    
    return variables, since, now


def execute_graphql_query(query: str, variables: Dict, api_token: str) -> Optional[Dict]:
    """
    Execute a GraphQL query against Cloudflare API.
    
    Returns:
        Response data or None on error
    """
    try:
        response = requests.post(
            CLOUDFLARE_GRAPHQL_URL,
            headers=get_graphql_headers(api_token),
            json={"query": query, "variables": variables},
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            return None
            
        return response.json()
    except Exception:
        return None


def parse_firewall_events(data: Dict) -> List[Dict]:
    """Parse firewall events from GraphQL response."""
    try:
        viewer = data.get("data", {}).get("viewer")
        if not viewer:
            return []

        zones = viewer.get("zones")
        if not zones:
            return []

        zones_list = zones if isinstance(zones, list) else [zones]
        events = []
        
        for zone in zones_list:
            firewall_events = zone.get("firewallEventsAdaptive")
            if firewall_events and isinstance(firewall_events, list):
                events.extend(firewall_events)
                
        return events
    except Exception:
        return []


def fetch_security_events(
    zone_id: str,
    api_token: str,
    minutes: int = DEFAULT_LOOKBACK_MINUTES,
    limit: int = DEFAULT_EVENT_LIMIT,
    custom_query: Optional[str] = None
) -> List[Dict]:
    """
    Fetch Cloudflare firewall events using GraphQL API.
    
    Args:
        zone_id: Cloudflare Zone ID
        api_token: Cloudflare API token
        minutes: Time window in minutes
        limit: Maximum number of events
        custom_query: Optional custom GraphQL query
        
    Returns:
        List of firewall event dictionaries
        
    Raises:
        RuntimeError: If query fails
    """
    query = custom_query or get_default_firewall_query()
    variables, _, _ = build_query_variables(zone_id, limit, minutes)
    
    data = execute_graphql_query(query, variables, api_token)
    
    if not data:
        raise RuntimeError("Failed to execute GraphQL query")
    
    if data.get("errors"):
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    
    if not data.get("data"):
        raise RuntimeError("No data in GraphQL response")
    
    events = parse_firewall_events(data)
    
    if not events:
        return []
    
    return events


def introspect_schema(api_token: str) -> Optional[Dict]:
    """Perform GraphQL schema introspection."""
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        types {
          name
          kind
          fields {
            name
            args {
              name
              type { name kind ofType { name kind } }
            }
          }
        }
      }
    }
    """
    
    return execute_graphql_query(introspection_query, {}, api_token)


# ============================================================================
# Event Processing Functions
# ============================================================================

def count_events_by_ip(events: List[Dict]) -> Dict[str, int]:
    """Count events grouped by IP address."""
    ip_counts = {}
    for event in events:
        ip = event.get("clientIP")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    return ip_counts


def group_events_by_ip(events: List[Dict]) -> Dict[str, List[Dict]]:
    """Group events by IP address."""
    ip_events = {}
    for event in events:
        ip = event.get("clientIP")
        if ip:
            ip_events.setdefault(ip, []).append(event)
    return ip_events


def build_report_comment(events: List[Dict]) -> str:
    """Build comment for AbuseIPDB report from events."""
    if not events:
        return "Suspicious activity detected"
    
    sample = events[0]
    source = sample.get("source", "unknown")
    host = sample.get("clientRequestHTTPHost", "")
    path = sample.get("clientRequestPath", "")
    
    comment = f"{len(events)} attack(s) blocked. Source: {source}."
    if host:
        comment += f" Target: {host}{path[:100]}"
    
    return comment


# ============================================================================
# Display Functions
# ============================================================================

def print_table_border(widths: List[int], style: str = "top") -> None:
    """Print table border line."""
    chars = TABLE_BORDER_CHARS
    h = chars["horizontal"]
    
    border_map = {
        "top": (chars["top_left"], chars["t_down"], chars["top_right"]),
        "middle": (chars["t_right"], chars["cross"], chars["t_left"]),
        "bottom": (chars["bottom_left"], chars["t_up"], chars["bottom_right"])
    }
    
    left, middle, right = border_map[style]
    # Add 2 for padding (1 space on each side)
    parts = [h * (w + 2) for w in widths]
    print(left + middle.join(parts) + right)


def get_visible_length(text: str) -> int:
    """Get visible length of string excluding ANSI color codes."""
    import re
    ansi_escape = re.compile(r'\033\[[0-9;]*m')
    return len(ansi_escape.sub('', text))


def print_table_row(values: List[str], widths: List[int], alignments: List[str]) -> None:
    """Print table data row."""
    v = TABLE_BORDER_CHARS["vertical"]
    formatted = []
    
    for value, width, align in zip(values, widths, alignments):
        visible_len = get_visible_length(value)
        padding_needed = width - visible_len
        
        if align == "right":
            formatted.append(f" {' ' * padding_needed}{value} ")
        else:
            formatted.append(f" {value}{' ' * padding_needed} ")
    
    print(v + v.join(formatted) + v)


def display_ip_summary_table(ip_counts: Dict[str, int], abuseipdb_key: Optional[str]) -> None:
    """Display IP summary as formatted table."""
    sorted_ips = sorted(ip_counts.items(), key=lambda x: (-x[1], x[0]))
    
    if abuseipdb_key:
        widths = [45, 8, 25, 35, 8]
        alignments = ["left", "right", "left", "left", "right"]
        headers = ["IP Address", "Count", "Country", "ISP", "Score"]
        
        print_table_border(widths, "top")
        print_table_row(headers, widths, alignments)
        print_table_border(widths, "middle")
        
        for ip, count in sorted_ips:
            abuse_info = check_ip_reputation(ip, abuseipdb_key)
            
            if abuse_info:
                country = abuse_info.country[:23]
                isp = abuse_info.isp[:33]
                
                # Colorize score based on value
                score_value = abuse_info.abuse_score
                if score_value == 0:
                    score = f"{COLOR_GREEN}{score_value}%{COLOR_RESET}"
                elif score_value == 100:
                    score = f"{COLOR_RED}{score_value}%{COLOR_RESET}"
                else:
                    score = f"{COLOR_ORANGE}{score_value}%{COLOR_RESET}"
            else:
                country = isp = score = "N/A"
            
            print_table_row([ip, str(count), country, isp, score], widths, alignments)
        
        print_table_border(widths, "bottom")
    else:
        widths = [45, 8, 40]
        alignments = ["left", "right", "left"]
        headers = ["IP Address", "Count", "Visual"]
        
        print_table_border(widths, "top")
        print_table_row(headers, widths, alignments)
        print_table_border(widths, "middle")
        
        for ip, count in sorted_ips:
            bars = "■" * min(count, 38)
            print_table_row([ip, str(count), bars], widths, alignments)
        
        print_table_border(widths, "bottom")
    
    total_ips = len(sorted_ips)
    total_events = sum(ip_counts.values())
    print(f"\nTotal: {total_ips} unique IP(s), {total_events} event(s)")


def display_detailed_events(events: List[Dict]) -> None:
    """Display detailed event information."""
    print(f"{len(events)} event(s) found:")
    print("-" * 80)
    
    for event in events:
        timestamp = event.get("datetime", "N/A")
        ip = event.get("clientIP", "N/A")
        country = event.get("clientCountryName", "N/A")
        action = event.get("action", "N/A")
        source = event.get("source", "N/A")
        rule_id = event.get("ruleId", "N/A")
        
        print(f"[{timestamp}] {ip} ({country})")
        print(f"  Action: {action} | Source: {source} | Rule: {rule_id}")
        
        ray_name = event.get("rayName")
        if ray_name:
            print(f"  Ray: {ray_name}")
        
        http_method = event.get("clientRequestHTTPMethodName", "")
        http_host = event.get("clientRequestHTTPHost", "")
        path = event.get("clientRequestPath", "")
        
        if http_method or http_host or path:
            print(f"  Request: {http_method} {http_host}{path}")
        
        user_agent = event.get("userAgent", "N/A")
        print(f"  User-Agent: {user_agent}")
        print("-" * 80)


def display_events(events: List[Dict], show_details: bool, abuseipdb_key: Optional[str]) -> None:
    """
    Display events in appropriate format.
    
    Args:
        events: List of firewall events
        show_details: If True, show detailed view; otherwise show IP summary
        abuseipdb_key: Optional AbuseIPDB API key for enrichment
    """
    if not events:
        print("No security events found in the selected time window.")
        return
    
    if show_details:
        display_detailed_events(events)
    else:
        ip_counts = count_events_by_ip(events)
        display_ip_summary_table(ip_counts, abuseipdb_key)


# ============================================================================
# Report Functions
# ============================================================================

def report_ips_to_abuseipdb(events: List[Dict], api_key: str) -> None:
    """Report all malicious IPs to AbuseIPDB."""
    ip_events = group_events_by_ip(events)
    
    print(f"Reporting {len(ip_events)} unique IP(s) to AbuseIPDB...")
    print("-" * 80)
    
    success_count = 0
    reported_ips = []
    
    for ip, ip_event_list in ip_events.items():
        comment = build_report_comment(ip_event_list)
        timestamp = ip_event_list[0].get("datetime")
        
        print(f"📤 Reporting {ip} ({len(ip_event_list)} event(s))...")
        
        if report_ip_to_abuseipdb(ip, api_key, comment, timestamp):
            print(f"  ✅ Successfully reported {ip}")
            success_count += 1
            reported_ips.append({
                "ip": ip,
                "timestamp": timestamp,
                "event_count": len(ip_event_list),
                "comment": comment
            })
    
    print("-" * 80)
    print(f"Report complete: {success_count}/{len(ip_events)} IPs reported successfully")
    
    # Write reported IPs to log file
    if reported_ips:
        try:
            with open("report.log", "a", encoding="utf-8") as f:
                current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                f.write(f"\n{'=' * 80}\n")
                f.write(f"Report Date: {current_time}\n")
                f.write(f"Total IPs Reported: {len(reported_ips)}\n")
                f.write(f"{'=' * 80}\n\n")
                
                for entry in reported_ips:
                    f.write(f"IP: {entry['ip']}\n")
                    f.write(f"  Event Count: {entry['event_count']}\n")
                    f.write(f"  First Event: {entry['timestamp']}\n")
                    f.write(f"  Comment: {entry['comment']}\n")
                    f.write(f"{'-' * 80}\n")
            
            print(f"\n📝 Report logged to: report.log")
        except Exception as e:
            print(f"\n⚠️  Warning: Could not write to report.log: {e}")


# ============================================================================
# CLI Functions
# ============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="Fetch Cloudflare security events via GraphQL API",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--api-token",
        required=True,
        help="Cloudflare API token with read permissions"
    )
    
    parser.add_argument(
        "--zone-id",
        required=True,
        help="Cloudflare Zone ID"
    )
    
    parser.add_argument(
        "--minutes",
        type=int,
        default=DEFAULT_LOOKBACK_MINUTES,
        help=f"Lookback window in minutes (default: {DEFAULT_LOOKBACK_MINUTES})"
    )
    
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_EVENT_LIMIT,
        help=f"Maximum number of events to fetch (default: {DEFAULT_EVENT_LIMIT})"
    )
    
    parser.add_argument(
        "--graphql-query-file",
        help="Path to file containing custom GraphQL query"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Display detailed event information (default: IP summary)"
    )
    
    parser.add_argument(
        "--abuseipdb-key",
        help="AbuseIPDB API key to enrich IP data"
    )
    
    parser.add_argument(
        "--report",
        action="store_true",
        help="Report malicious IPs to AbuseIPDB (requires --abuseipdb-key)"
    )
    
    parser.add_argument(
        "--introspect",
        action="store_true",
        help="Perform GraphQL schema introspection and exit"
    )
    
    return parser


def load_custom_query(file_path: str) -> Optional[str]:
    """Load custom GraphQL query from file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Error reading query file: {e}")
        return None


def handle_introspection(api_token: str) -> None:
    """Handle schema introspection mode."""
    print("Performing GraphQL schema introspection...")
    schema = introspect_schema(api_token)
    
    if schema:
        print(json.dumps(schema, indent=2))
    else:
        print("Failed to introspect schema")


def handle_report_mode(events: List[Dict], api_key: Optional[str]) -> None:
    """Handle report mode."""
    if not api_key:
        print("Error: --report requires --abuseipdb-key")
        sys.exit(1)
    
    report_ips_to_abuseipdb(events, api_key)


def main() -> None:
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle introspection mode
    if args.introspect:
        handle_introspection(args.api_token)
        return
    
    try:
        # Load custom query if specified
        custom_query = None
        if args.graphql_query_file:
            custom_query = load_custom_query(args.graphql_query_file)
        
        # Fetch events
        events = fetch_security_events(
            zone_id=args.zone_id,
            api_token=args.api_token,
            minutes=args.minutes,
            limit=args.limit,
            custom_query=custom_query
        )
        
        # Handle report mode
        if args.report:
            handle_report_mode(events, args.abuseipdb_key)
            return
        
        # Display events (default: IP summary, --debug: detailed)
        display_events(
            events=events,
            show_details=args.debug,
            abuseipdb_key=args.abuseipdb_key
        )
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
