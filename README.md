# Palo Alto Add-on for Splunk

This is a Splunk Technology Add-on (TA) that collects data from Palo Alto Networks devices via API and ingests it into Splunk.

## Prerequisites

- Splunk Enterprise or Splunk Cloud
- Palo Alto Networks firewall or Panorama with API access
- API key with appropriate permissions
- Python 3.7+ with `ucc-gen` installed

## Installation

### Install UCC Generator

```bash
pip install splunk-add-on-ucc-framework
```

### Build the Add-on

```bash
ucc-gen build --source palo_alto_addon_for_splunk
```

This command:
- Reads `globalConfig.json` in the source directory
- Generates REST handlers, UI components, and configuration files
- Outputs the complete add-on to `output/palo_alto_addon_for_splunk/`
- Installs Python dependencies from `package/lib/requirements.txt`

### Package for Distribution

```bash
ucc-gen package --path output/palo_alto_addon_for_splunk
```

This creates a `.tar.gz` file that can be installed in Splunk.

### Install in Splunk

1. Install the `.tar.gz` file through Splunk Web (Apps > Manage Apps > Install app from file)
2. Or copy `output/palo_alto_addon_for_splunk/` to `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk

## Adding a New Palo Alto Input

### Step 1: Configure an Account

1. In Splunk Web, navigate to **Apps** > **Palo Alto Add-on for Splunk**
2. Go to the **Configuration** tab
3. Click **Add** under the **Account** section
4. Fill in:
   - **Name**: A unique identifier for this account (e.g., `prod_firewall_account`)
   - **Account Type**: Select either `firewall` or `panorama`
   - **API Key**: Enter your Palo Alto API key (will be encrypted and stored securely)
5. Click **Add**

### Step 2: Configure API Endpoints (Optional)

The add-on comes with pre-configured API endpoints. You can add custom endpoints if needed:

1. Go to the **Configuration** tab > **API Endpoints** section
2. Click **Add**
3. Fill in:
   - **Name**: Unique endpoint identifier (e.g., `custom_system_info`)
   - **API URL**: The API URL with variables (e.g., `https://${host}/api/?type=op&cmd=<show><system><info></info></system></show>&key=${api_key}`)
   - **Script Type**: Select the handler function (e.g., `GET_api_generic`)
4. Click **Add**

**Note**: URLs support `${host}` and `${api_key}` placeholders that are replaced at runtime.

#### Available Script Types

When configuring API endpoints, you must select a script type that determines how the API response is processed:

| Script Type | Purpose | Data Format | Use Cases |
|-------------|---------|-------------|-----------|
| `GET_api_generic` | Simple HTTPS GET request that returns raw XML | Returns raw XML response for Splunk to parse using `KV_MODE=xml` | System info, session stats, configuration queries, any standard Palo Alto API endpoint that returns XML |
| `custom_GET_api_threat_traffic` | Advanced threat/traffic log query with filtering | Returns filtered JSON events for high/critical severity threats | Threat monitoring, security alerts. Queries last 30 minutes, polls asynchronous jobs, filters for high/critical severity only |

**Notes:**
- `GET_api_generic` is the most common choice for standard API queries
- `custom_GET_api_threat_traffic` uses Palo Alto's asynchronous log query API with job polling
- Custom script types can be added by implementing new handler functions in `api_handlers.py`

### Step 3: Create a Data Input

1. Go to the **Inputs** tab
2. Click **Create New Input**
3. Fill in the following fields:

   - **Name**: Unique input name (e.g., `prod_firewall_system_metrics`)
   - **Interval**: Data collection interval in seconds (e.g., `300` for 5 minutes)
   - **Index**: Splunk index for the data (e.g., `main` or `metrics`)
   - **IP Address**: Device IP address(es)
     - Single IP: `192.168.1.1`
     - Multiple IPs (comma-separated, max 20): `192.168.1.1, 192.168.1.2, 192.168.1.3`
     - All IPs will use the same configuration and be queried in parallel

   - **Account**: Select the account you created in Step 1

   - **API Endpoints**: Select one or more API endpoints to query
     - Available endpoints: `system_info`, `session_info`, `threat_logs`, etc.
     - Multiple endpoints will be queried sequentially for each IP address

   - **Sourcetype**: Select the appropriate sourcetype
     - `pan:log` (default) - General logs
     - `pan:traffic` - Traffic logs
     - `pan:threat` - Threat logs
     - `pan:system` - System logs
     - `pan:config` - Configuration logs
     - `pan:session` - Session logs

   - **Index Type**: Choose data format
     - **Events** (default): Raw XML data parsed by Splunk
       - Use for detailed logs and records
       - Searchable with standard SPL commands
     - **Metrics**: Numeric values in JSON format
       - Use for time-series data (CPU, memory, session counts, etc.)
       - Searchable with `| mstats`, `| mcatalog`
       - Best practice: Use a metrics index

4. Click **Add**

### Step 4: Verify Data Collection

1. Wait for the interval period to pass
2. Search for the data in Splunk:

   **For Events:**
   ```spl
   index=main sourcetype=pan:system
   ```

   **For Metrics:**
   ```spl
   | mstats avg(metric_name:*) WHERE index=metrics sourcetype=pan:system
   ```

3. Check internal logs for any errors:
   ```spl
   index=_internal source=*palo_alto_addon_for_splunk*
   ```

## Configuration Examples

### Example 1: Single Firewall, System Metrics
- **Name**: `fw01_system_metrics`
- **Interval**: `300`
- **IP Address**: `10.1.1.1`
- **Account**: `prod_firewall`
- **API Endpoints**: `system_info`, `session_info`
- **Sourcetype**: `pan:system`
- **Index Type**: `Metrics`
- **Index**: `metrics`

### Example 2: Multiple Firewalls, Threat Logs
- **Name**: `firewall_cluster_threats`
- **Interval**: `600`
- **IP Address**: `10.1.1.1, 10.1.1.2, 10.1.1.3`
- **Account**: `prod_firewall`
- **API Endpoints**: `threat_logs`
- **Sourcetype**: `pan:threat`
- **Index Type**: `Events`
- **Index**: `main`

### Example 3: Panorama, Configuration Auditing
- **Name**: `panorama_config_audit`
- **Interval**: `3600`
- **IP Address**: `10.1.2.1`
- **Account**: `panorama_account`
- **API Endpoints**: `config_audit`
- **Sourcetype**: `pan:config`
- **Index Type**: `Events`
- **Index**: `main`

## Multiple IP Addresses

You can monitor up to 20 Palo Alto devices with a single input:

- **Format**: Comma-separated IPv4 addresses
- **Example**: `192.168.1.1, 192.168.1.2, 192.168.1.3`
- **Maximum**: 20 IP addresses per input
- **Behavior**:
  - All devices are queried in parallel
  - All use the same account, API endpoints, sourcetype, and index
  - The `host` field in Splunk events is set to the device IP address
  - Failures on one device don't affect others

## Development Workflow

1. **Modify Configuration**: Edit `palo_alto_addon_for_splunk/globalConfig.json`
2. **Update Custom Code**: Edit `palo_alto_addon_for_splunk/package/bin/*.py`
3. **Rebuild**: Run `ucc-gen build --source palo_alto_addon_for_splunk`
4. **Test in Splunk**: Deploy `output/palo_alto_addon_for_splunk/` to `$SPLUNK_HOME/etc/apps/`
5. **Package**: Run `ucc-gen package --path output/palo_alto_addon_for_splunk` when ready to distribute

**Important**: Never edit files in `output/` directly - they are regenerated on each build.

## Troubleshooting

### No Data Appearing

1. Check if the input is enabled
2. Verify the API key is correct and has proper permissions
3. Check firewall rules allow HTTPS (443) from Splunk to Palo Alto devices
4. Review internal logs:
   ```spl
   index=_internal source=*palo_alto_addon_for_splunk* ERROR
   ```

### SSL Certificate Errors

By default, SSL certificate verification is disabled to support self-signed certificates. If you see SSL warnings:
- This is expected behavior
- For production, consider using trusted certificates and enabling SSL verification in `api_handlers.py`

### API Key Visible in Logs

API keys are automatically masked in Splunk indexed data using SEDCMD. Raw log files on disk may contain the key for debugging purposes, but indexed data shows `key=********`.

## Support

For issues or questions, refer to the [Splunk UCC Framework documentation](https://splunk.github.io/addonfactory-ucc-generator/) or contact your Splunk administrator.
