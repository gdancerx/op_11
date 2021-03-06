import unittest
import log_analyzer
import datetime
from decimal import Decimal


class Log_Analyzer_Test(unittest.TestCase):
    def setUp(self):
        self.config = {
                        "REPORT_SIZE": 10,
                        "REPORT_DIR": "./reports",
                        "LOG_DIR": "./log",
                        "TEMPLATE": "report.html",
                        "ERRORS_THRESHOLD": 25,
                        "LOG_FILE": "log_analyzer.log",
                        "TIME_STAMPDIR": ""
                      }

    def test_read_config_file_if_config_file_is_not_exists(self):
        self.assertEqual(log_analyzer.read_config_file("hjfueybcvnsdf",
                         self.config), None)

    def test_find_last_log_log_dir_is_not_exists(self):
        self.config['LOG_DIR'] = "djdfkhueytrhbhfjdfd"
        self.assertEqual(log_analyzer.find_last_log(self.config), (None, None))

    def test_get_last_filename_if_files_is_empty(self):
        self.assertEqual(log_analyzer.get_last_filename([]), (None, None))

    def test_get_last_filename(self):
        files = [
                 'nginx-access-ui.log-20170814.gz',
                 'nginx-access-ui.log-20170815',
                 'nginx-access-ui.log-20170504.gz',
                 'nginx-access-ui.log-20180102.gz'
        ]
        self.assertEqual(log_analyzer.get_last_filename(files),
                         ('nginx-access-ui.log-20180102.gz',
                          datetime.datetime(2018, 1, 2, 0, 0)))

    def test_open_log_file_if_log_file_is_not_exists(self):
        self.assertEqual(log_analyzer.open_log_file("kdfhgfkjdhgd"), None)

    def test_process_log_file_if_log_file_is_not_exists(self):
        self.assertEqual(log_analyzer.process_log_file("hfjghdfjhjgdf"),
                         (None, None))

    def test_process_log_line_do_not_match(self):
        line = '1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/group/1769230/banners HTTP/1.1" 200 1020 "-" "Configovod" "712e90144abee9" 0.628'
        self.assertEqual(log_analyzer.process_log_line(line), (None, None))

    def test_process_log_line_match(self):
        line = '1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/group/1769230/banners HTTP/1.1" 200 1020 "-" "Configovod" "-" "1498697422-2118016444-4708-9752747" "712e90144abee9" 0.628'
        self.assertEqual(log_analyzer.process_log_line(line), ('/api/v2/group/1769230/banners ', '0.628'))

    def test_process_line_data_url_is_None(self):
        stat_data_before = {
                            'total_requests': 0,
                            'parsing_errors': 0
        }
        stat_data_after = {
                           'total_requests': 1,
                           'parsing_errors': 1
        }
        self.assertEqual(log_analyzer.process_line_data(stat_data_before,
                                                        None,
                                                        {},
                                                        '0'),
                         (None, stat_data_after))

    def test_process_line_data_url_is_non_None(self):
        stat_data_before = {
                            'sum_requests_number': 10,
                            'sum_requests_time': Decimal(50),
                            'total_requests': 1,
                            'parsing_errors': 0
        }
        stat_data_after = {
                           'sum_requests_number': 11,
                           'sum_requests_time': Decimal(51),
                           'total_requests': 2,
                           'parsing_errors': 0
        }
        url = '/api/v2/group/1769230/banners '
        report_data_before = {
                              url:
                              {
                               'count': 1,
                               'time_sum': Decimal('0.628'),
                               'time_max': Decimal('0.628'),
                               'count_perc': 0,
                               'time_perc': Decimal(0),
                               'time_avg': Decimal(0),
                               'time_med': Decimal('0.628')
                               }
        }
        report_data_after = {
                             'count': 2,
                             'time_sum': Decimal('1.628'),
                             'time_max': Decimal('1.000'),
                             'count_perc': 0,
                             'time_perc': Decimal(0),
                             'time_avg': Decimal(0),
                             'time_med': log_analyzer.calc_median(
                                          '1.000',
                                          Decimal('1.628'),
                                          2,
                                          report_data_before[url]['time_med'])
        }

        self.assertEqual(log_analyzer.process_line_data(stat_data_before,
                                                        url,
                                                        report_data_before,
                                                        '1.000'),
                         (report_data_after, stat_data_after))

    def test_analyze_log_line_first_time(self):
        url = '/api/v2/group/1769230/banners '
        result = {
                  'count': 1,
                  'time_sum': Decimal('0.628'),
                  'time_max': Decimal('0.628'),
                  'count_perc': 0,
                  'time_perc': Decimal(0),
                  'time_avg': Decimal(0),
                  'time_med': log_analyzer.calc_median('0.628',
                                                       Decimal('0.628'),
                                                       1,
                                                       Decimal(0))
        }
        self.assertEqual(log_analyzer.analyze_log_line({}, url, '0.628'),
                         result)

    def test_analyze_log_line_non_first_time(self):
        url = '/api/v2/group/1769230/banners '
        data_before = {
                       url:
                       {
                        'count': 1,
                        'time_sum': Decimal('0.628'),
                        'time_max': Decimal('0.628'),
                        'count_perc': 0,
                        'time_perc': Decimal(0),
                        'time_avg': Decimal(0),
                        'time_med': Decimal('0.628')
                        }
        }
        data_after = {
                      'count': 2,
                      'time_sum': Decimal('1.628'),
                      'time_max': Decimal('1.000'),
                      'count_perc': 0,
                      'time_perc': Decimal(0),
                      'time_avg': Decimal(0),
                      'time_med': log_analyzer.calc_median(
                                   '1.000',
                                   Decimal('1.628'),
                                   2,
                                   data_before[url]['time_med'])
        }
        self.assertEqual(log_analyzer.analyze_log_line(data_before,
                                                       url,
                                                       '1.000'),
                         data_after)

    def test_calc_median_requesttime_less_than_time_med(self):
        self.assertEqual(log_analyzer.calc_median(100, 10000, 10, 5000), 4900)

    def test_calc_median_requesttime_more_than_time_med(self):
        self.assertEqual(log_analyzer.calc_median(6000, 10000, 10, 5000), 5100)

    def test_summarize_url_calculations(self):
        url_data_before = {
                           'count': 10,
                           'time_sum': Decimal('10'),
                           'time_max': Decimal('1.000'),
                           'count_perc': 0,
                           'time_perc': Decimal(0),
                           'time_avg': Decimal(0),
                           'time_med': Decimal(100)
        }
        url_data_after = {
                          'count': 10,
                          'time_sum': Decimal('10'),
                          'time_max': Decimal('1.000'),
                          'count_perc': 10.0,
                          'time_perc': Decimal(20.0),
                          'time_avg': Decimal(1),
                          'time_med': Decimal(100)
        }
        stat_data = {
                     'sum_requests_number': 100,
                     'sum_requests_time': Decimal(50),
                     'total_requests': 1,
                     'parsing_errors': 0
        }
        self.assertEqual(log_analyzer.summarize_url(url_data_before, stat_data),
                         url_data_after)

    def test_summarize_data_calculations(self):
        report_data_before = {
                              '/api/v2/group/1769230/banners':
                              {
                               'count': 10,
                               'time_sum': Decimal('10'),
                               'time_max': Decimal('1.000'),
                               'count_perc': 0,
                               'time_perc': Decimal(0),
                               'time_avg': Decimal(0),
                               'time_med': Decimal(100)
                               },
                              '/export/appinstall_raw/2017-06-29/':
                              {
                               'count': 20,
                               'time_sum': Decimal('5'),
                               'time_max': Decimal('1.000'),
                               'count_perc': 0,
                               'time_perc': Decimal(0),
                               'time_avg': Decimal(0),
                               'time_med': Decimal(100)
                               },
        }
        report_data_after = {
                             '/api/v2/group/1769230/banners':
                             {
                              'count': 10,
                              'time_sum': Decimal('10'),
                              'time_max': Decimal('1.000'),
                              'count_perc': 10.0,
                              'time_perc': Decimal('20.0'),
                              'time_avg': Decimal(1),
                              'time_med': Decimal(100)
                              },
                             '/export/appinstall_raw/2017-06-29/':
                             {
                              'count': 20,
                              'time_sum': Decimal('5'),
                              'time_max': Decimal('1.000'),
                              'count_perc': 20.0,
                              'time_perc': Decimal(10.0),
                              'time_avg': Decimal(0.25),
                              'time_med': Decimal(100)
                              }
        }
        stat_data = {
                     'sum_requests_number': 100,
                     'sum_requests_time': Decimal(50),
                     'total_requests': 1,
                     'parsing_errors': 0
        }
        self.maxDiff = None
        self.assertEqual(log_analyzer.summarize_data(report_data_before,
                                                     stat_data),
                         report_data_after)

    def test_construct_list_calculations(self):
        url = '/api/v2/group/1769230/banners '
        data_before = {
                       'count': 10,
                       'time_sum': Decimal('10.4445454'),
                       'time_max': Decimal('1.58498'),
                       'count_perc': 7.343488,
                       'time_perc': Decimal('20.54575'),
                       'time_avg': Decimal(1.5454675),
                       'time_med': Decimal(45.45453467)
        }
        data_after = {
                      'url': url,
                      'count': 10,
                      'time_sum': 10.445,
                      'time_max': 1.585,
                      'count_perc': 7.343,
                      'time_perc': 20.546,
                      'time_avg': 1.545,
                      'time_med': 45.455
        }
        self.maxDiff = None
        self.assertEqual(log_analyzer.construct_list(url, data_before),
                         data_after)

    def test_get_top_n_urls_calculations(self):
        data_before = {
                       '/api/v2/group/1769230/banners':
                       {
                        'count': 10,
                        'time_sum': Decimal('10'),
                        'time_max': Decimal('1.27'),
                        'count_perc': 10.0,
                        'time_perc': Decimal(24.0),
                        'time_avg': Decimal(1),
                        'time_med': Decimal(100)
                        },
                       '/export/appinstall_raw/2017-06-29/':
                       {
                        'count': 20,
                        'time_sum': Decimal('5'),
                        'time_max': Decimal('1.000'),
                        'count_perc': 20.0,
                        'time_perc': Decimal(10.0),
                        'time_avg': Decimal(0.25),
                        'time_med': Decimal(110)
                        },
                       '/api/v2/group/7870727/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28':
                       {
                        'count': 30,
                        'time_sum': Decimal('7'),
                        'time_max': Decimal('0.345'),
                        'count_perc': 30.0,
                        'time_perc': Decimal(9.0),
                        'time_avg': Decimal(2.25),
                        'time_med': Decimal(21)
                        }
        }
        data_after = [
                      {
                       'url': '/api/v2/group/1769230/banners',
                       'count': 10,
                       'time_sum': 10.0,
                       'time_max': 1.27,
                       'count_perc': 10.0,
                       'time_perc': 24.0,
                       'time_avg': 1.0,
                       'time_med': 100.0
                       },
                      {
                       'url': '/api/v2/group/7870727/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28',
                       'count': 30,
                       'time_sum': 7.0,
                       'time_max': 0.345,
                       'count_perc': 30.0,
                       'time_perc': 9.0,
                       'time_avg': 2.25,
                       'time_med': 21.0
                       }
        ]
        self.maxDiff = None
        self.assertEqual(log_analyzer.get_top_n_urls(data_before, 2),
                         data_after)

    def test_generate_report_if_template_is_not_exists(self):
        config = {
                   "TEMPLATE": "4389dshdsjd",
                   "REPORT_DIR": "./ssssss"
        }
        self.assertRaises(OSError, log_analyzer.generate_report([], None,
                          config))

    def test_put_timestamp_if_timestamp_dir_is_not_exists(self):
        self.assertRaises(OSError, log_analyzer.put_timestamp('jfkshjdshsdhj'))

    def test_calc_errors_perc_calculations(self):
        self.assertEqual(log_analyzer.calc_errors_perc(20, 34233), 0.06)

    def test_parse_args_if_None(self):
        self.assertEqual(log_analyzer.CONFIG_NAME, log_analyzer.parse_args([]))

    def test_parse_args_if_config_is_not_empty(self):
        self.assertEqual("xxx", log_analyzer.parse_args(["--config", "xxx"]))
