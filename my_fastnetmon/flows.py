__all__ = ['process_details']

import re
import logging
import os
import my_fastnetmon.exabgp as exabgp
import my_fastnetmon.config as config
from my_fastnetmon.database import *
import sqlite3
from datetime import datetime

logger = logging.getLogger("log")

DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

#
# parse detail attack log string from fastnetmon
# 
# return list of vars from string
#
def parse_flow_vars(items):
    flow_vars = {}
    # minimum items in attack detail string is 5
    if (len(items)<5):
        return
    flow_vars['date'] = items[0]
    flow_vars['time'] = items[1]
    (flow_vars['src_ip'],flow_vars['src_port']) = items[2].split(':')
    (flow_vars['dst_ip'],flow_vars['dst_port']) = items[4].split(':')
    items_iter = iter(items[5:])
    for item in items_iter:
        if (len(item)>1 and item[-1] == ':'):
            flow_vars[item[0:-1]] = next(items_iter)
    return flow_vars

#
# create new empty flow record
#
# return new empty flow
#
def new_flow(flow_vars):
    flow = {}
    flow['dst_ip'] = flow_vars['dst_ip']
    flow['protocol'] = flow_vars['protocol']
    flow['src_ports'] = {}
    flow['dst_ports'] = {}
    flow['min_packet'] = flow_vars['size']
    flow['max_packet'] = flow_vars['size']
    flow['packets'] = 0
    flow['octets'] = 0
    flow['flags'] = {}
    #2020-02-22 20:53:30.000000
    flow['start_datetime'] = datetime.strptime(flow_vars.get('date')+' '+flow_vars.get('time'),DATETIME_FORMAT)
    flow['end_datetime'] = datetime.strptime(flow_vars.get('date')+' '+flow_vars.get('time'),DATETIME_FORMAT)
    return flow

#
# process parsed string in <flow_vars> and update info in <flows> list
#
# return list <flows>
#
def calc_flow(flows,key,flow_vars):
    flow = flows.get(key)
    if not flow:
        flow = new_flow(flow_vars)
    if flow_vars.get('flags'):
        flow['flags'][flow_vars['flags']] = 1
    flow['src_ports'][int(flow_vars['src_port'])] = 1
    flow['dst_ports'][int(flow_vars['dst_port'])] = 1
    if flow['max_packet'] < int(flow_vars['size']):
        flow['max_packet'] = int(flow_vars['size'])
    if flow['min_packet'] > int(flow_vars['size']):
        flow['min_packet'] = int(flow_vars['size'])
    flow['packets'] = flow['packets']+int(flow_vars['packets'])*int(flow_vars['ratio'])
    flow['octets']  = flow['octets']+int(flow_vars['size'])*int(flow_vars['ratio'])
    flow_datetime = datetime.strptime(flow_vars.get('date')+' '+flow_vars.get('time'),DATETIME_FORMAT)
    if (flow.get('start_datetime')>flow_datetime):
        flow['start_datetime'] = flow_datetime
    if (flow.get('end_datetime')<flow_datetime):
        flow['end_datetime'] = flow_datetime
    flows[key] = flow
    return flows

#
# process detail log from fastnetmon
#
# return (dict main vars, dict flows)
#
def process_details(lines):
    main = {}
    flows = {}
    for line in lines:
        main_vars = line.strip().split(': ')
        if (len(main_vars) == 2):
            #logger.debug('%s - %s',main_vars[0],main_vars[1])
            main[main_vars[0]] = main_vars[1]
        else:
            flow_vars = parse_flow_vars(line.strip().split(' '))
            if flow_vars:
                key1 = flow_vars.get('dst_ip') + '_' + flow_vars.get('protocol') + '_' + flow_vars.get('src_port');
                key2 = flow_vars.get('dst_ip') + '_' + flow_vars.get('protocol') + '_' + flow_vars.get('dst_port');
                flows = calc_flow(flows,key1,flow_vars)
                flows = calc_flow(flows,key2,flow_vars)
    return (main,flows)
