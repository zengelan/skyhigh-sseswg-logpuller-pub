#!/usr/bin/env python3

# DESCRIPTION:
# Skyhigh SSE SWG Logpuller Script.
#
# Script to get Skyhigh SSE SWG logs from Skyhigh REST API.
# Logs are downloaded to 'OutputLog.$NowUnixEpoch$.csv' and can be forwarded
# to a remote syslog host or SIEM when 'syslogEnable' is set to 'True'.
# When forwarding is used the downloaded CSV is transformed into a JSON stream.
# Configure your syslog/SIEM input correspondingly.
#
# The script is using Skyhigh REST API ver. 11; Field reference:
# https://success.skyhighsecurity.com/Skyhigh_Secure_Web_Gateway_(Cloud)/Using_the_REST_API_for_Reporting/Reporting_Fields
#
# 
# CHANGELOG:
# 2.0b  2024-01-25 - To adjust for Skyhigh Security, multiple regions and support for FWaaS, RBI and PrivateAccess logs
# 1.1  2020-05-03 - Config option to set the output dir for downloaded CSV files
# 1.0  2020-05-02 - initial release (Happy Birthday Adam!)
#

import argparse
import configparser
import csv
import json
import logging
import os
import socket
import time
from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth

# small help for script; path to custom configuration file can be passed
helper = argparse.ArgumentParser(description='''Skyhigh SSE SWG Log Puller Script.''')
helper.add_argument('--config', help='path to custom configuration file (default: <scriptname>.conf)', nargs='?',
                    default=os.path.splitext(__file__)[0] + '.conf')
args = helper.parse_args()

# set path to custom config or default to $scriptname$.conf
config_filename = args.config

# log will be $scriptname$.log
log = os.path.splitext(__file__)[0] + '.log'

# set logging style 2024-01-25 13:52:12,729 <LEVEL>: <message>
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', filename=log, level=logging.INFO)

# first log lines
logging.info('log=' + log)
logging.info('config=' + config_filename)

# first line of responses should be like this when API version 11 is used:
field_reference = {
    'swg': '"user_id","username","source_ip","http_action","server_to_client_bytes","client_to_server_bytes",'
           '"requested_host","requested_path","result","virus","request_timestamp_epoch","request_timestamp",'
           '"uri_scheme","category","media_type","application_type","reputation","last_rule","http_status_code",'
           '"client_ip","location","block_reason","user_agent_product","user_agent_version","user_agent_comment",'
           '"process_name","destination_ip","destination_port","pop_country_code","referer","ssl_scanned",'
           '"av_scanned_up","av_scanned_down","rbi","dlp","client_system_name","filename","pop_egress_ip",'
           '"pop_ingress_ip","proxy_port","mw_probability","discarded_host","ssl_client_prot","ssl_server_prot",'
           '"domain_fronting_url"',
    'rbi': '"user_id","username","source_ip","http_action","bytes_sc","bytes_cs","requested_host","requested_path",'
           '"result","virus","request_timestamp_epoch","request_timestamp","uri_scheme","category","media_type",'
           '"application_type","reputation","last_rule","http_status_code","client_ip","location","block_reason",'
           '"user_agent_product","user_agent_version","user_agent_comment","process_name","destination_ip",'
           '"destination_port","pop_country_code","referer","ssl_scanned","av_scanned_up","av_scanned_down","rbi",'
           '"dlp","client_system_name","filename","pop_egress_ip","pop_ingress_ip","proxy_port","mw_probability",'
           '"discarded_host","ssl_client_prot","ssl_server_prot","domain_fronting_url","site","action",'
           '"action_reason","request_url","risk_score","mcp_yn","isolate_type","filename_upload","filename_download",'
           '"filesize_upload","filesize_download"',
    'pa': '"request_timestamp","username","pa_application_name","requested_host","request_url","pa_app_group",'
          '"pa_used_connector","device_profile","host_os_name","bytes_sc","bytes_cs","http_status_code",'
          '"action","block_reason","virus"',
    'firewall': '"request_timestamp","username","client_ip","destination_ip","process_name","client_port",'
                '"destination_port","firewall_action","client_country","destination_country","application_name",'
                '"policy_name","protocol","detected_protocol","connectivity_method","location","egress_client_port",'
                '"tunnel_ingress_port","bytes_sc","bytes_cs","transaction_id", "client_host_name","host_os_name",'
                '"scp_policy_name","process_exe_path"',
}

# request header for CSV download and API version
requestHeaders = {'user-agent': 'logpuller/2.0.0.b', 'Accept': 'text/csv', 'x-mwg-api-version': '11'}

Now = int(time.time())
requestTimestampTo = Now
filename = 'OutputLog.$Region$.$TrafficType$.$Now$.csv'


def read_config():
    global config_filename
    global saasCustomerID, saasUserID, saasPassword, saasLoggingRegions, saasTrafficTypes, \
        chunkIncrement, connectionTimeout, outputDirCSV, proxyURL, syslogEnable, syslogHost, syslogPort, \
        syslogProto, syslogKeepCSV, filename
    try:
        with open(config_filename, 'r') as f:
            cfgfile = f.read()

            parser = configparser.RawConfigParser(allow_no_value=True)

            # make option names case sensitive
            # (https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.optionxform)
            parser.optionxform = str
            parser.read_string(cfgfile)

            saasCustomerID = parser.getint('saas', 'saasCustomerID')
            logging.info('saasCustomerID=' + str(saasCustomerID))

            saasUserID = parser.get('saas', 'saasUserID')
            logging.info('saasUserID=' + saasUserID)

            saasPassword = parser.get('saas', 'saasPassword')

            saasLoggingRegions = parser.get('saas', 'saasLoggingRegions')
            logging.info('saasLoggingRegions=' + saasLoggingRegions)

            saasTrafficTypes = parser.get('saas', 'saasTrafficTypes')
            logging.info('saasTrafficTypes=' + saasTrafficTypes)

            chunkIncrement = parser.getint('request', 'chunkIncrement')
            logging.info('chunkIncrement=' + str(chunkIncrement))

            connectionTimeout = parser.getint('request', 'connectionTimeout', fallback=180)
            logging.info('connectionTimeout=' + str(connectionTimeout))

            outputDirCSV = parser.get('request', 'outputDirCSV')
            logging.info('outputDirCSV=' + outputDirCSV)
            if outputDirCSV:
                filename = os.path.join(outputDirCSV, filename)

            proxyURL = parser.get('proxy', 'proxyURL')

            syslogEnable = parser.getboolean('syslog', 'syslogEnable')
            logging.info('syslogEnable=' + str(syslogEnable))

            syslogHost = parser.get('syslog', 'syslogHost')
            logging.info('syslogHost=' + syslogHost)

            syslogPort = parser.getint('syslog', 'syslogPort')
            logging.info('syslogPort=' + str(syslogPort))

            syslogProto = parser.get('syslog', 'syslogProto')
            logging.info('syslogProto=' + syslogProto)

            syslogKeepCSV = parser.getboolean('syslog', 'syslogKeepCSV')
            logging.info('syslogKeepCSV=' + str(syslogKeepCSV))

    except Exception as e:
        logging.critical('readConfig(' + config_filename + ')')
        logging.critical(str(e))
        print('Exception: readConfig(' + config_filename + ')')


def write_config_item(attribute, value):
    global config_filename
    logging.debug('write_config_item(' + os.path.basename(config_filename) + ',' + attribute + '=' + str(value) + ')')
    try:
        with open(config_filename, 'r') as f:
            cfgfile = f.read()
            parser = configparser.RawConfigParser(allow_no_value=True)
            # make option names case-sensitive
            parser.optionxform = str
            # get config in-memory
            parser.read_string(cfgfile)
            # set new attribute in request section
            parser.set('request', attribute, value)
            # open config file in writ mode
            cfgfile = open(config_filename, 'w')
            # write from in-memory to file
            parser.write(cfgfile)
            cfgfile.close()
    except Exception as e:
        logging.critical('Error in write_config_item(' + os.path.basename(config_filename) +
                         ',' + attribute + '=' + str(value) + ')')
        logging.critical(str(e))


def read_config_item(attribute):
    global config_filename
    logging.debug('read_config_item(' + os.path.basename(config_filename) + ',' + attribute + ')')
    try:
        with open(config_filename, 'r') as f:
            parser = configparser.RawConfigParser(allow_no_value=True)
            parser.optionxform = str
            parser.read_file(f)
            ret = parser.getint('request', attribute, fallback=0)
            return ret
    except Exception as e:
        logging.critical('Error in read_config_item(' + os.path.basename(config_filename) + ',' + attribute + ')')
        logging.critical(str(e))


def syslogForwarder(saasFilename):
    logging.info('Parsing CSV to JSON stream and forwarding to: ' + syslogHost + ', Port ' + str(
        syslogPort) + ' (' + syslogProto + ')')
    try:
        # read downloaded CSV and parse it into list
        with open(saasFilename, 'r') as csvFile:
            csvReader = csv.DictReader(csvFile)
            rows = list(csvReader)

        # now for each row in list make corresponding JSON stream and forward via TCP or UDP
        for row in rows:
            message = json.dumps(row)
            if syslogProto == 'TCP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((syslogHost, syslogPort))
                sock.send(message)
                sock.close()
            elif syslogProto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message, (syslogHost, syslogPort))

        if not syslogKeepCSV:
            logging.info('Clean up: deleting ' + saasFilename)
            os.remove(saasFilename)

    except Exception as e:
        logging.critical(str(e))


def getHostForRegion(region: str):
    return "{}.logapi.skyhigh.cloud".format(region)


def getLogsByRegionAndType(region: str, traffic_type=str('swg')):
    global filename, chunkIncrement, requestHeaders, saasCustomerID, Now
    totalLines = 0
    saasFilename = None
    config_ts_entry_name = 'requestTimestampFrom.{}.{}'.format(region, traffic_type)
    requestTimestampFrom = read_config_item(config_ts_entry_name)
    # set start for Now - 24 hours if requestTimestampFrom is 0
    if requestTimestampFrom == 0:
        requestTimestampFrom = Now - (60 * 60 * 24 * 10)

    # add headrer for different log types:
    if traffic_type != 'swg':
        requestHeaders[traffic_type] = "1"

    # must make requests in chunked increments
    chunkCount = 0

    for requestChunk in range(requestTimestampFrom, Now, chunkIncrement):
        chunkCount += 1
        startTime = requestChunk
        endTime = requestChunk + chunkIncrement - 1 if requestChunk + chunkIncrement < Now else Now

        saasFilename = filename.replace(
            '$Now$', str(Now)).replace(
            '$Region$', region).replace(
            '$TrafficType$', traffic_type)

        # change requestTimestampFrom and requestTimestampTo to requestChunk start/stop times
        try:
            requestLogLine = ' requestChunk: ' + str(chunkCount) + ', ' + str(
                datetime.utcfromtimestamp(startTime)) + '(' + str(startTime) + ') - ' + str(
                datetime.utcfromtimestamp(endTime)) + '(' + str(endTime) + ')'

            url = 'https://{}/mwg/api/reporting/forensic/{}'.format(getHostForRegion(region), saasCustomerID)
            urlparams = {'filter.requestTimestampFrom': startTime,
                         'filter.requestTimestampTo': endTime,
                         'order.0.requestTimestamp': 'asc'}

            r = requests.get(url, params=urlparams, headers=requestHeaders, proxies=requestProxies,
                             auth=HTTPBasicAuth(saasUserID, saasPassword), timeout=connectionTimeout)

            logging.info(" request took {} to complete".format(r.elapsed))

            if r.status_code != 200:
                logging.error('Invalid response status: ' + str(r.status_code) + r.text)
                raise ValueError('Invalid response status: ' + str(r.status_code))

            responseLines = r.text.splitlines()
            # if response is valid but has only 1 line, then it's just a header and should be ignored.
            if len(responseLines) <= 2 and responseLines[0] == '':
                logging.debug(requestLogLine + ': no data, next chunk')
                continue

            # first line of response should be fieldHeader
            if responseLines[0] != field_reference[traffic_type]:
                logging.warning(
                    requestLogLine + ": invalid first line for type '{}' : '{}'".format(traffic_type, responseLines[0]))

            totalLines += len(responseLines) - 2
            requestLogLine += ', response: ' + str(r.status_code) + ', responseLines: ' + \
                              str(len(responseLines)) + ', totalLines: ' + str(totalLines)
            logging.debug(requestLogLine)

            # if file does not exist, write the log headers
            if not os.path.isfile(saasFilename):
                logging.info('creating output file: ' + saasFilename)
                try:
                    # with open(saasFilename, 'w+b') as outputFile:
                    with open(saasFilename, 'w') as outputFile:
                        outputFile.write(responseLines[0] + '\n')
                except Exception as e:
                    logging.critical("Exception: can't write outputFile: " + saasFilename + ': ' + str(e))

            # write the log records
            # with open(saasFilename, 'a+b') as outputFile:
            with open(saasFilename, 'a') as outputFile:
                logging.info('appending to output file: ' + saasFilename)
                # exclude first line. it's the field headers
                for line in range(1, len(responseLines)):
                    # exclude any blank lines
                    if responseLines[line] == '':
                        continue
                    outputFile.write(responseLines[line] + '\n')

            logging.info("Success: File: {}, From: {}({}), To: {}({}), totalLines: {}, chunkCount: {}".format(
                saasFilename, datetime.utcfromtimestamp(startTime), startTime,
                datetime.utcfromtimestamp(endTime), endTime, totalLines, chunkCount)
            )

        except Exception as e:
            logging.critical(str(e))

        if syslogEnable:
            syslogForwarder(saasFilename)

    # finally set requestTimestampFrom for next run to current time of execution
    write_config_item(config_ts_entry_name, endTime)


if __name__ == '__main__':

    # parse config file
    logging.info("Reading config file")
    read_config()

    if not proxyURL:
        logging.info('Using direct connect for request, no proxy configured')
        requestProxies = None
    else:
        # set proxy servers for request if needed
        requestProxies = {'http': proxyURL, 'https': proxyURL}
        logging.info('Using proxy for request')

    for query_region in saasLoggingRegions.split(','):
        for query_log_type in saasTrafficTypes.split(','):
            logging.info("Requesting log type '{}' for region '{}'".format(query_log_type, query_region))
            getLogsByRegionAndType(region=query_region, traffic_type=query_log_type)

    logging.info('Finished with queries, shutting down')
