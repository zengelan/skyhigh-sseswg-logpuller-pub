# Skyhigh SSE SWG Logpuller Script

Script to get Skyhigh SSE SWG logs from Skyhigh REST API. Logs are downloaded to ```'OutputLog.$NowUnixEpoch$.csv'``` and can be forwarded to a remote syslog host or SIEM when ```syslogEnable``` is set to ```'True'```.

> **Note:**
>
> When forwarding is used the downloaded CSV is transformed into a JSON stream. Configure your syslog/SIEM input correspondingly.

Timestamp is automatically adjusted with the last successful time of request. The corresponding configuration option ```requestTimestampFrom``` is updated after each run of the script.

The script is using Skyhigh REST API ver. 11

Field reference:
<https://success.skyhighsecurity.com/Skyhigh_Secure_Web_Gateway_(Cloud)/Using_the_REST_API_for_Reporting/Reporting_Fields>

General API reference and list of regions:
<https://success.skyhighsecurity.com/Skyhigh_Secure_Web_Gateway_(Cloud)/Using_the_REST_API_for_Reporting/About_Working_with_the_REST_API>

## Usage

- Install python3, version 3.10 or higher
- Download script and configuration file.
- Make script executable and adjust the configuration file to your needs.
- Run it periodically via cron for example.

## Configuration

This table explains the necessary configuration options:
| Section | Option | Value Type | Description | Example |
|---------|--------|------------|-------------|---------|
| ```saas``` | ```saasCustomerID``` | INT (Mandatory) | Your Skyhigh SSE customer ID without the leading 'c' | ```123456789``` |
|  | ```saasUserID``` | STR (mandatory) | Usually your tenant e-mail address | ```foo@example.com``` |
|  | ```saasPassword``` | STR (mandatory) | Your Skyhigh SSE tenant password | ```my53cr37p455``` |
|  | ```saasLoggingRegions``` | STR (mandatory) | A list of regions to pull logs from, separated by comma | ```us,de,gb,sg,ae,in,au,sa``` |
|  | ```saasTrafficTypes``` | STR (mandatory) | A list of log types, separated by comma | ```swg,rbi,pa,firewall``` |
| ```request``` | ```requestTimestampFrom``` | INT (optional) | Epoch timestamp of last successful request; dynamically set to last execution time; if initially set to 0 value is dynamically adjusted to ```Now - 24h``` | ```1588458908``` |
|  | ```chunkIncrement``` | INT (mandatory) | Requests are splitted into chunks if time between last request and execution is bigger than this value (seconds) | ```3600``` |
|  | ```connectionTimeout``` | INT (mandatory) | Time to wait for request response (seconds) | ```180``` |
|  | ```outputDirCSV``` | STR (optional) | Specify different output directory for downloaded CSV file ```'OutputLog.$NowUnixEpoch$.csv'``` **IMPORTANT**: directoy must exist! | ```/var/tmp/sseswglogs``` |
| ```proxy``` | ```proxyURL``` | STR (optional) | If you are behind a proxy you can configure a corresponding URL here (format: ```http://PROXY_SERVER:PORT``` or ```http://USER:PASSWORD@PROXY_SERVER:PORT)``` | ```http://proxy.example.com:8080``` |
| ```syslog``` | ```syslogEnable``` | BOOL (mandatory) | Enable message forwarding in form of a JSON stream; either 'True' or 'False' | ```True``` |
|  | ```syslogHost``` | STR (mandatory) | IP or hostname of remote syslog host/Log Management/SIEM | ```siem.mycompany.local``` |
|  | ```syslogPort``` | INT (mandatory) | Port for remote syslog input | ```5555``` |
|  | ```syslogProto``` | STR (mandatory) | Must be either ```'TCP'``` or ```'UDP'``` | ```UDP``` |
|  | ```syslogKeepCSV``` | BOOL (mandatory) | Keep the downloaded CSV (```'True'```) or delete after forwarding (```'False'```) | ```False``` |


## Credits and Links

Special thanks go to [@1ce8erg0](https://github.com/1ce8erg0), [@tux78](https://github.com/tux78), Jeff Ebeling and Erik Elsasser from McAfee/Trellix/Skyhigh for providing the codebase for this project and the forks thereof.

- A PowerShell implementation can be found here - <https://github.com/tux78/WGCSLogPull>
