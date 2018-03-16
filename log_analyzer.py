#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import sys
import configparser
import logging
import os
import datetime
import gzip
import re
from decimal import Decimal, getcontext
import heapq
from string import Template
import pprint
import time

config = {
    "REPORT_SIZE": 10,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "TEMPLATE": "report.html",
    "ERRORS_THRESHOLD": 25,
    "LOG_FILE": "log_analyzer.log",
    "TIME_STAMPDIR": ""
}

CONFIG_NAME = 'log_analyzer.cfg'

def exception_handler(exc_type, value, tb):
    logging.error('Uncaught exception:', exc_info=(exc_type, value, tb))

def read_config_file(config_file, config):
    new_config = config.copy()
    if os.path.exists(config_file):
        with open(config_file) as cf:
            cfg = configparser.ConfigParser()
            cfg.optionxform = str
            try:
                cfg.read_file(cf)
                if 'log_analyzer' in cfg.sections():
                    new_config.update(cfg['log_analyzer'])
                else:
                    logging.error('Wrong format of configuration file ' + config_file + '. Exiting.')
                    return None
            except IOError:
                logging.exception('Error reading configuration file ' + config_file + '. Exiting.')
                return None
    else:
        logging.error('Configuration file ' + config_file + ' isn\'t exists. Exiting.')
        return None
    return new_config

def set_logging(config):
    f = config.get('LOG_FILE')
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S', filename=f)


def find_last_log(config):
    #files = ['nginx-access-ui.log-20170814.gz', 'nginx-access-ui.log-20170815', 'nginx-access-ui.log-20170504.gz', 'nginx-access-ui.log-20180102.gz']
    try:
        logging.info("Checking log directory " + config['LOG_DIR'])
        files = os.listdir(config['LOG_DIR'])
    except FileNotFoundError:
        logging.exception('Log directory ' + config['LOG_DIR'] + ' is not exists!')
        return None, None
    
    dfiles = []
    last_file = ('', datetime.datetime(1900, 1, 1, 0, 0, 0))

    if files:
        dfiles = [(file, datetime.datetime.strptime(file[20:28], '%Y%m%d')) for file in files if file.startswith('nginx-access-ui.log-')]
        for file in dfiles:
            if file[1] > last_file[1]:
                last_file = file
    else:
        logging.info('Log directory ' + config['LOG_DIR'] + ' is empty.')
        return None, None

    return last_file

def open_log_file(log_name):
    try:
        if log_name[-3:].lower() == '.gz':
            log_file = gzip.open(log_name, 'rt')
        else:
            log_file = open(log_name, 'rt')
    except OSError:
        logging.exception('Error reading file ' + log_name + '!')
        return None
    return log_file


def process_log_file(log_name):

    report_data = {}
    stat_data = {'sum_requests_number': 0,
                 'sum_requests_time': Decimal(0),
                 'parsing_errors': 0,
                 'total_requests': 0
                }

    log_file = open_log_file(log_name)
    if log_file is None:
        return None, None
    logging.info('Processing log file: ' + log_name)
    try:
        for line in log_file:
            url, requesttime = process_log_line(line)
            stat_data['total_requests'] = stat_data['total_requests'] + 1
            if url is not None:
                updated_data = analyze_log_line(report_data, url, requesttime)
                report_data[url] = updated_data
                stat_data['sum_requests_number'] = stat_data['sum_requests_number'] + 1
                stat_data['sum_requests_time'] = stat_data['sum_requests_time'] + Decimal(requesttime)
            else:
                stat_data['parsing_errors'] = stat_data['parsing_errors'] + 1
                #print(line)

    except OSError:
        logging.exception('Error reading file ' + log_name + '!')
        return None, None
    finally:
        log_file.close()
    return report_data, stat_data

def process_log_line(line):
    regex = r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<ruser>.+) (?P<xrip>.+) \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST|HEAD|PUT) )(?P<url>.+)(http\/1\..\")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) ([\"](?P<referer>(\-)|(.+))[\"]) ([\"](?P<useragent>.+)[\"]) ([\"](?P<f1>.+)[\"]) ([\"](?P<f2>.+)[\"]) ([\"](?P<f3>.+)[\"]) (?P<requesttime>\d+.\d+)'
    line_parsed = re.match(regex, line, re.I)
    if line_parsed:
        return line_parsed.group('url', 'requesttime')        
    else:
        return None, None
    
def analyze_log_line(report_data, url, requesttime):
    url_data = report_data.get(url)
    if url_data is not None:
        url_data['count'] = url_data['count'] + 1
        url_data['time_sum'] = url_data['time_sum'] + Decimal(requesttime)
        url_data['time_max'] = Decimal(requesttime) if Decimal(requesttime) > url_data['time_max'] else url_data['time_max']
        url_data['time_med'] = calc_median(requesttime, url_data['time_sum'], url_data['count'], url_data['time_med'])
    else:
        url_data = {'count': 1, 
                    'time_sum': Decimal(requesttime),
                    'time_max': Decimal(requesttime),
                    'count_perc': 0,
                    'time_perc': Decimal(0),
                    'time_avg': Decimal(0),
                    'time_med': calc_median(requesttime, Decimal(requesttime), 1, Decimal(0))
                    }
        
    return url_data

def calc_median(requesttime, time_sum, count, time_med):
    delta = time_sum / count / count
    median = time_med - delta if Decimal(requesttime) < time_med else time_med + delta
    return median

def summarize_data(report_data, stat_data):
    sum_data = {url: summarize_url(url_data, stat_data) for (url, url_data) in report_data.items()}
    return sum_data

def summarize_url(url_data, stat_data):
    data = url_data.copy()
    data['count_perc'] = url_data['count'] / stat_data['sum_requests_number'] * 100
    data['time_perc'] = url_data['time_sum'] / stat_data['sum_requests_time'] * 100
    data['time_avg'] = url_data['time_sum'] / url_data['count']
    return data


def construct_list(url, data):
    temp_dict = {}
    temp_dict['url'] = url
    temp_dict['count'] =  data['count']
    temp_dict['count_perc'] = round(data['count_perc'], 3)
    temp_dict['time_avg'] = float(data['time_avg'].quantize(Decimal('0.001')))
    temp_dict['time_max'] = float(data['time_max'].quantize(Decimal('0.001')))
    temp_dict['time_med'] = float(data['time_med'].quantize(Decimal('0.001')))
    temp_dict['time_perc'] = float(data['time_perc'].quantize(Decimal('0.001')))
    temp_dict['time_sum'] = float(data['time_sum'].quantize(Decimal('0.001')))    
    return temp_dict

def get_top_n_urls(sum_data, n):
    top_n_urls = heapq.nlargest(int(n), sum_data, key=lambda url : sum_data[url]['time_sum'])
    return [construct_list(url,sum_data[url]) for url in top_n_urls]

def generate_report(data, log_date, config):
    try:
        with open(config['TEMPLATE']) as html_template:
            logging.info('Using template ' + config['TEMPLATE'])
            t = Template(html_template.read())
            report_html = t.safe_substitute(table_json=data)
            try:
                report_name = 'report-' + log_date.strftime('%Y.%m.%d') + '.html'
                with open(os.path.join(config['REPORT_DIR'], report_name), 'wt') as report:
                    logging.info('Generating report ' + report_name)
                    report.write(report_html)
            except OSError:
                logging.exception('Error writing file ' + report + '!')
    except OSError:
        logging.exception('Error reading file ' + html_template + '!')

def put_timestamp(timestamp_dir):
    ts_file = os.path.join(timestamp_dir, 'log_analyzer.ts')
    try:
        with open(ts_file, 'wt') as ts:
            ts.write(str(time.time()))
    except OSError:
        logging.exception('Error writing timestamp '+ ts_file)

def check_if_report_exists(report_dir, log_date):
    logging.info("Checking report directory " + report_dir)
    report_name = os.path.join(report_dir, 'report-' + log_date.strftime('%Y.%m.%d') + '.html')
    return os.path.exists(report_name)

def calc_errors_perc(num_errors, total_requests):
    return round(num_errors / total_requests * 100, 2)

def main():
  
    sys.excepthook = exception_handler
    working_config = config.copy()

    config_name = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1].lower() == '--config' else CONFIG_NAME
    working_config = read_config_file(config_name, working_config)
    if working_config is None:
        sys.exit(1)

    set_logging(working_config)
    
    logging.info('Started processing...')

    log_name, log_date = find_last_log(working_config)
    if log_name is None:
        logging.info('No log file to process. Exiting.')
        logging.info('Finished processing...')
        sys.exit(1)

    if not check_if_report_exists(working_config['REPORT_DIR'], log_date):

        log_data, stat_data = process_log_file(os.path.join(working_config['LOG_DIR'], log_name))
        
        if log_data is None:
            logging.error('Error processing log file. Exiting.')
            logging.error('Finished processing...')
            sys.exit(1)
        elif calc_errors_perc(stat_data['parsing_errors'], stat_data['total_requests']) > float(working_config['ERRORS_THRESHOLD']):
            print(calc_errors_perc(stat_data['parsing_errors'], stat_data['total_requests']))
            logging.error('Too many parsing errors: ' + calc_errors_perc(stat_data['parsing_errors'], stat_data['total_requests']) + ' > ' + working_config['ERRORS_THRESHOLD'] + ' Exiting.')
            logging.error('Finished processing...')
            sys.exit(1)

        sum_data = summarize_data(log_data, stat_data)
        report_data = get_top_n_urls(sum_data, working_config['REPORT_SIZE'])
        generate_report(report_data, log_date, working_config)

        put_timestamp(working_config['TIMESTAMP_DIR'])
    else:
        logging.info('Report file exists. Nothing to process.')

    logging.info('Finished processing...')

if __name__ == "__main__":
    main()
