# Cloudflare Security Events - GraphQL API

## Description

Python script to fetch Cloudflare firewall security events via the GraphQL API.

## ✅ Working Script

The script has been successfully corrected to use Cloudflare's GraphQL API and now retrieves firewall security events.

## Required API Token Permissions

### Steps to create a Cloudflare API token with correct permissions:

1. Log in to your Cloudflare account: https://dash.cloudflare.com/

2. Go to **My Profile** > **API Tokens**
   - Direct URL: https://dash.cloudflare.com/profile/api-tokens

3. Click **"Create Token"**

4. Choose a template or create a custom token with the following permissions:

   **Required Permissions:**
   - `Zone` > `Zone` > `Read`
   - `Zone` > `Analytics` > `Read` ✓ **IMPORTANT**
   - `Zone` > `Firewall Services` > `Read` (optional but recommended)

5. **Zone Resources:**
   - Select "All zones" or specifically your zone

6. Click **"Continue to summary"** then **"Create Token"**

7. **Copy the new token** and use it in your commands

## Usage

### Basic Command

```bash
python3 cloudflare-abuseipdb-report.py \
  --api-token "YOUR_TOKEN_WITH_PERMISSIONS" \
  --zone-id "your-zone-id" \
  --minutes 1440 \
  --limit 100
```

### Available Options

- `--api-token`: Cloudflare API token (required)
- `--zone-id`: Cloudflare Zone ID (required)
- `--minutes`: Time window in minutes (default: 10, max: 1440)
- `--limit`: Maximum number of events to fetch (default: 50)
- `--ip-only`: Extract and display only unique IP addresses with attack count
- `--graphql-query-file`: File containing a custom GraphQL query
- `--introspect`: Display available GraphQL schema (diagnostic mode)

### Examples

#### Fetch events from the last 24 hours
```bash
python3 cloudflare-abuseipdb-report.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --minutes 1440 \
  --limit 100
```

#### Extract IP addresses with attack count
```bash
python3 cloudflare-abuseipdb-report.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --minutes 1440 \
  --ip-only
```

#### Diagnostic mode (schema introspection)
```bash
python3 cloudflare-abuseipdb-report.py \
  --api-token "your_token" \
  --zone-id "your-zone-id" \
  --introspect > schema.json
```

## GraphQL Query Used

The script uses the following GraphQL query:

```graphql
query FirewallEvents($zoneTag: string, $limit: int, $filter: ZoneFirewallEventsAdaptiveFilter_InputObject) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(limit: $limit, filter: $filter) {
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

## Dependencies

```bash
pip install requests
```

## Output Format

The script displays events in a readable format:

```
10 event(s) found:
--------------------------------------------------------------------------------
[2025-12-10T22:00:00Z] 192.168.1.1 (France)
  Action: block | Source: firewall | Rule: abc123
  Ray: 9ac0000000000000-AMS
  Request: GET example.com/api/endpoint
  User-Agent: Mozilla/5.0...
--------------------------------------------------------------------------------
```

## Diagnostic Features

The script includes several diagnostic functions:

1. **Zone Access Verification**: Confirms the token can access the specified zone
2. **GraphQL Schema Introspection**: Allows discovering available fields
3. **Detailed Error Messages**: Displays GraphQL and HTTP errors for easier debugging

## Limits and Constraints

### Maximum Time Window
Cloudflare's GraphQL API limits the time window to **24 hours (1440 minutes)** maximum per query.

If you try to query a longer period, you will get the error:
```
query time range is too large... Time range can't be wider than 86400s
```

**Solution**: Limit `--minutes` to 1440 maximum.

## Troubleshooting

### Error: "not authorized for that account"
➜ The token doesn't have the `Analytics` > `Read` permission at zone level. Create a new token with the permissions listed above.

### Error: "unknown field"
➜ The GraphQL schema has changed. Use `--introspect` to see available fields.

### No events found
➜ Check the time window (`--minutes`) and ensure there were security events during that period.

### Error: "query time range is too large"
➜ The time window exceeds 24h. Reduce `--minutes` to 1440 or less.

## Version History

- **Corrected version**: Migration to GraphQL API with `viewer.zones[].firewallEventsAdaptive`
- Added GraphQL schema introspection
- Support for GraphQL field names (camelCase)
- Improved diagnostics with permission verification

## Resources

- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [GraphQL Analytics API](https://developers.cloudflare.com/analytics/graphql-api/)
- [Create API Tokens](https://dash.cloudflare.com/profile/api-tokens)
