# Cloudflare Security Events - AbuseIPDB Reporter

## Description

Advanced Python script to monitor Cloudflare firewall security events via GraphQL API with AbuseIPDB integration for threat intelligence and automated IP reporting.

## ✅ Features

- **Smart Event Filtering**: Automatically filters out "hot" source events
- **IP Summary Dashboard**: Default table view with attack count per IP
- **AbuseIPDB Integration**: 
  - IP reputation enrichment (country, ISP, abuse score)
  - Automated malicious IP reporting
  - Color-coded threat levels (🟢 safe, 🟠 suspicious, 🔴 malicious)
- **Detailed Event View**: Debug mode with full event information
- **Audit Logging**: Automatic report.log for all AbuseIPDB submissions
- **GraphQL Schema Introspection**: Built-in diagnostic tools

## Required API Token Permissions

### Cloudflare API Token

1. Log in to your Cloudflare account: https://dash.cloudflare.com/

2. Go to **My Profile** > **API Tokens**
   - Direct URL: https://dash.cloudflare.com/profile/api-tokens

3. Click **"Create Token"**

4. Create a custom token with the following permissions:

   **Required Permissions:**
   - `Zone` > `Zone` > `Read`
   - `Zone` > `Analytics` > `Read` ✓ **IMPORTANT**
   - `Zone` > `Firewall Services` > `Read` (optional but recommended)

5. **Zone Resources:**
   - Select "All zones" or specifically your zone

6. Click **"Continue to summary"** then **"Create Token"**

7. **Copy the new token** and use it in your commands

### AbuseIPDB API Key (Optional)

For IP enrichment and reporting features:
1. Sign up at https://www.abuseipdb.com/
2. Navigate to your API settings
3. Generate an API key
4. Use with `--abuseipdb-key` option

## Usage

### Quick Start (Default: IP Summary)

```bash
python3 cloudflare-alert.py \
  --api-token "YOUR_CLOUDFLARE_TOKEN" \
  --zone-id "your-zone-id"
```

Default behavior:
- Shows last **24 hours** (1440 minutes)
- Fetches up to **1000 events**
- Displays **IP summary table** with attack counts

### Available Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--api-token` | ✅ Yes | - | Cloudflare API token with Analytics read permission |
| `--zone-id` | ✅ Yes | - | Cloudflare Zone ID |
| `--minutes` | No | 1440 | Lookback window in minutes (max: 1440) |
| `--limit` | No | 1000 | Maximum number of events to fetch |
| `--abuseipdb-key` | No | - | AbuseIPDB API key for IP enrichment |
| `--debug` | No | false | Show detailed event information instead of IP summary |
| `--report` | No | false | Report malicious IPs to AbuseIPDB (requires `--abuseipdb-key`) |
| `--graphql-query-file` | No | - | Path to custom GraphQL query file |
| `--introspect` | No | false | Display GraphQL schema and exit |

### Examples

#### Basic IP Summary (Default)
```bash
python3 cloudflare-alert.py \
  --api-token "your_token" \
  --zone-id "your-zone-id"
```

**Output:**
```
┌───────────────────────────┬──────────┬──────────────────────┐
│ IP Address                │    Count │ Visual               │
├───────────────────────────┼──────────┼──────────────────────┤
│ 192.168.1.100             │       45 │ ■■■■■■■■■■■■■■■■■    │
│ 10.0.0.50                 │       12 │ ■■■■■■■■■■■■         │
└───────────────────────────┴──────────┴──────────────────────┘

Total: 2 unique IP(s), 57 event(s)
```

#### Enriched IP Summary with AbuseIPDB
```bash
python3 cloudflare-alert.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --abuseipdb-key "your_abuseipdb_key"
```

**Output:**
```
┌──────────────────────┬───────┬────────────┬──────────────────┬────────┐
│ IP Address           │ Count │ Country    │ ISP              │  Score │
├──────────────────────┼───────┼────────────┼──────────────────┼────────┤
│ 4.235.98.10          │    32 │ Norway     │ Microsoft Corp   │   100% │  🔴
│ 15.235.151.203       │    20 │ Singapore  │ OVH              │   100% │  🔴
│ 129.212.239.206      │     8 │ Singapore  │ DigitalOcean     │    72% │  🟠
│ 12.74.98.86          │     1 │ USA        │ AT&T             │     0% │  🟢
└──────────────────────┴───────┴────────────┴──────────────────┴────────┘
```

#### Detailed Event View (Debug Mode)
```bash
python3 cloudflare-alert.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --debug
```

**Output:**
```
52 event(s) found:
--------------------------------------------------------------------------------
[2025-12-10T22:00:00Z] 192.168.1.1 (France)
  Action: block | Source: firewallCustom | Rule: 7e2f6a176e57438aae51869f3a0bdbb3
  Ray: 9ac0000000000000-AMS
  Request: GET example.com/api/endpoint
  User-Agent: Mozilla/5.0...
--------------------------------------------------------------------------------
```

#### Report Malicious IPs to AbuseIPDB
```bash
python3 cloudflare-alert.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --abuseipdb-key "your_abuseipdb_key" \
  --report
```

**Output:**
```
Reporting 15 unique IP(s) to AbuseIPDB...
--------------------------------------------------------------------------------
📤 Reporting 4.235.98.10 (32 event(s))...
  ✅ Successfully reported 4.235.98.10
📤 Reporting 15.235.151.203 (20 event(s))...
  ✅ Successfully reported 15.235.151.203
--------------------------------------------------------------------------------
Report complete: 15/15 IPs reported successfully

📝 Report logged to: report.log
```

#### Custom Time Window
```bash
python3 cloudflare-alert.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --minutes 60 \
  --limit 50
```

#### Diagnostic mode (schema introspection)
```bash
python3 cloudflare-alert.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --introspect > schema.json
```

## GraphQL Query

The script uses the following optimized GraphQL query with automatic filtering:

```graphql
query FirewallEvents($zoneTag: string, $limit: int, $since: Time, $until: Time) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        limit: $limit, 
        filter: {
          datetime_geq: $since, 
          datetime_leq: $until, 
          source_neq: "hot"  # Automatically filters out "hot" source events
        }
      ) {
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
}
```

## Output Formats

### 1. IP Summary Table (Default)

Clean table format with attack counts and visual indicators:
- Sorted by attack count (descending)
- Visual representation with UTF-8 block characters (■)
- Summary statistics at bottom

### 2. Enriched IP Table (with --abuseipdb-key)

Enhanced table with threat intelligence:
- **Country**: IP geolocation
- **ISP**: Internet Service Provider
- **Score**: AbuseIPDB confidence score with color coding:
  - 🟢 **Green (0%)**: Clean IP, no abuse reports
  - 🟠 **Orange (1-99%)**: Some suspicious activity
  - 🔴 **Red (100%)**: Highly malicious, confirmed threat

### 3. Detailed Event View (with --debug)

Full event details for forensic analysis:
- Timestamp and geolocation
- Action taken and rule triggered
- Ray ID for Cloudflare support
- Full HTTP request details
- User agent information

### 4. Report Log (report.log)

Automatic audit log when using `--report`:
```
================================================================================
Report Date: 2025-12-11 22:10:11 UTC
Total IPs Reported: 15
================================================================================

IP: 4.235.98.10
  Event Count: 32
  First Event: 2025-12-11T21:55:37Z
  Comment: 32 attack(s) blocked. Source: firewallCustom. Target: example.com/api
--------------------------------------------------------------------------------
```

## Dependencies

```bash
pip install requests
```

## Clean Code Architecture

The script follows clean code principles:
- **Separation of Concerns**: API, processing, display, and CLI logic separated
- **Single Responsibility**: Each function has one clear purpose
- **Type Hints**: Full type annotations for better code documentation
- **Constants**: All magic values extracted to module-level constants
- **Error Handling**: Comprehensive exception handling with clear error messages
- **Low Cyclomatic Complexity**: Functions kept under 20 lines with minimal nesting

## Limits and Constraints

### Maximum Time Window
Cloudflare's GraphQL API limits the time window to **24 hours (1440 minutes)** maximum per query.

If you try to query a longer period, you will get the error:
```
query time range is too large... Time range can't be wider than 86400s
```

**Solution**: The script defaults to 1440 minutes maximum.

### AbuseIPDB Rate Limits
- Free tier: 1,000 requests per day
- Registered tier: Higher limits available
- The script respects these limits by making one request per unique IP

## Troubleshooting

### Error: "not authorized for that account"
➜ The Cloudflare token doesn't have the `Analytics` > `Read` permission at zone level. Create a new token with the permissions listed above.

### Error: "unknown field"
➜ The GraphQL schema has changed. Use `--introspect` to see available fields.

### No events found
➜ Check the time window (`--minutes`) and ensure there were security events during that period. Also verify that events aren't being filtered by the `source_neq: "hot"` filter.

### Error: "query time range is too large"
➜ The time window exceeds 24h. The default is now 1440 minutes (24 hours).

### AbuseIPDB errors
➜ Verify your API key is valid. Check your rate limit quota at https://www.abuseipdb.com/account/api

### Report not logging
➜ Ensure you have write permissions in the current directory for `report.log`

## Version History

### v2.0.0 (Current)
- ✨ **New**: AbuseIPDB integration for IP enrichment
- ✨ **New**: Automated IP reporting to AbuseIPDB
- ✨ **New**: Color-coded threat levels in output
- ✨ **New**: Automatic report.log generation
- ✨ **New**: IP summary table as default view
- 🔧 **Changed**: Default lookback to 24 hours (1440 minutes)
- 🔧 **Changed**: Default limit increased to 1000 events
- 🔧 **Changed**: Auto-filter "hot" source events in GraphQL query
- 🎨 **Enhanced**: Clean code refactoring with type hints
- 🎨 **Enhanced**: Beautiful table formatting with UTF-8 borders

### v1.0.0
- Initial GraphQL API migration
- Schema introspection support
- Basic event display

## Resources

- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [GraphQL Analytics API](https://developers.cloudflare.com/analytics/graphql-api/)
- [Create API Tokens](https://dash.cloudflare.com/profile/api-tokens)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Cloudflare GraphQL API documentation
3. Open an issue on GitHub
