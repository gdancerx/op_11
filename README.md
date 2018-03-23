# log_analyzer.py - nginx log file analyzer
log_analyzer.py is a command-line utility for nginx log processing and statistics calculation.

### Usage: log_analyzer.py --config __config file name__

## Configuration file format:

```
[log_analyzer]
<variable 1>: <value 1>
...
<variable n>: <value n>
```
where variables are:
Variable | Description
---------|------------
REPORT_SIZE | a number of urls in report
REPORT_DIR | a directory for report output
LOG_DIR | a directory for log input
LOG_FILE | a log file name
TEMPLATE | a report template
ERRORS_THRESHOLD | parsing errors threshold
TIMESTAMP_DIR | a directory for timestamp file
