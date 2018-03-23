# log_analyzer.py - nginx log file analyzer
log_analyzer.py is a command-line utility for nginx log processing and statistics calculation.

*Requirements:* Python 3.x

### Usage: log_analyzer.py --config __config file name__

## Configuration file format:

```
[log_analyzer]
<variable 1>: <value 1>
...
<variable n>: <value n>
```
where variables are:

__REPORT_SIZE__ - a number of urls in report  
__REPORT_DIR__ - a directory for report output  
__LOG_DIR__ - a directory for log input  
__LOG_FILE__ - a log file name  
__TEMPLATE__ - a report template  
__ERRORS_THRESHOLD__ - parsing errors threshold  
__TIMESTAMP_DIR__ - a directory for timestamp file  
