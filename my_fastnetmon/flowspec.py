__all__ = ['process_flows']

import re
import logging
import os
import sqlite3
from datetime import datetime

import my_fastnetmon.exabgp as exabgp
import my_fastnetmon.config as config
from my_fastnetmon.database import *
from my_fastnetmon.ipaddress import *

logger = logging.getLogger("log")

GRE_FLOOD     = 'GRE_FLOOD'
UDP_FLOOD     = 'UDP_FLOOD'
DNS_FLOOD     = 'DNS_FLOOD'
TCP_SYN_FLOOD = 'TCP_SYN_FLOOD'

#
# create blackhole rule from vars in 'flow
#
def create_rule_blackhole(flow):
    dst_ip = flow.get('dst_ip') + '/32'
    dst_subnet = get_subnet(flow.get('dst_ip'))
    rule = []
    rule.extend(('route','destination',dst_ip))
    rule.extend(('community',config.BLACKHOLE_NEXTHOP));
    rule.extend(('community',config.BLACKHOLE_COMMUNITY));
    blackhole_rule = ' '.join(rule)
    logger.debug("Generate rule '%s'",blackhole_rule)
    return blackhole_rule;

#
# create flowspec rule from vars in 'flow' with 'attack_type'
#
def create_rule_flow(flow,attack_type):
    dst_ip = flow.get('dst_ip') + '/32'
    dst_subnet = get_subnet(flow.get('dst_ip'))
    rule = []
    rule.extend(('flow','route','destination',dst_subnet))
    if (attack_type == GRE_FLOOD):
        rule.extend(('protocol','[ gre ]'))
    elif (attack_type == UDP_FLOOD):
        rule.extend(('protocol','[ udp ]'))
        rule.extend(('source-port','[ ='+str(flow.get('src_ports').keys()[0])+' ]'))
    elif (attack_type == DNS_FLOOD):
        rule.extend(('protocol','[ udp ]'))
        rule.extend(('source-port','[ ='+str(flow.get('src_ports').keys()[0])+' ]'))
        rule.extend(('packet-length','[ >900 ]'))
    elif (attack_type == TCP_SYN_FLOOD):
        rule.extend(('protocol','[ tcp ]'))
        rule.extend(('destination-port','[ ='+str(flow.get('dst_ports').keys()[0])+' ]'))
        rule.extend(('tcp-flags','[ syn ]'))
    else:
         return ''
    rule.extend(('community',config.FLOW_COMMUNITY));
    rule.extend(('rate-limit','0'));
    flowspec_rule = ' '.join(rule)
    logger.debug("Generate rule '%s'",flowspec_rule)
    return flowspec_rule;

#
# process all flows, received from fastnetmon, and generate flowspec rules for them
#
def process_flows(flows):
    rules = []
    for key,flow in flows.items():

        seconds = int(flow.get('end_datetime').strftime('%s'))-int(flow.get('start_datetime').strftime('%s'))
        if seconds <=0:
            seconds = 1
        pps = flow.get('packets')/seconds
        bps = flow.get('octets')/seconds*8
#        logger.debug("FLOW packets %d start time %s - end time %s: PPS:%d BPS:%d",flow.get('packets'),flow.get('start_datetime').strftime('%s'),flow.get('end_datetime').strftime('%s'),pps,bps)
        if (pps > config.FLOW_BAN_PPS):
            attack_type = ''
            dst_ip = flow.get('dst_ip')
            # GRE proto (src and dst port == 0)
            if (flow.get('src_ports').get(0) == 1 and flow.get('dst_ports').get(0) == 1):
                attack_type = GRE_FLOOD
                logger.info('Detect GRE/UDP flood to %s',dst_ip)
                rules.append((dst_ip,create_rule_flow(flow,GRE_FLOOD),attack_type))
                rules.append((dst_ip,create_rule_flow(flow,UDP_FLOOD),attack_type))

            # UDP flood
            elif (flow.get('protocol') == 'udp' and len(flow.get('src_ports')) == 1):
                # DNS UDP flood set minimum packet len
                attack_type = 'UDP_FLOOD_'+str(flow.get('src_ports').keys()[0])
                if flow.get('src_ports').get(53) == 1:
                    logger.info('Detect UDP DNS flood to %s',dst_ip)
                    rules.append((dst_ip,create_rule_flow(flow,DNS_FLOOD),attack_type))
                else:
                    logger.info('Detect UDP flood from port %d to %s',flow.get('src_ports').keys()[0],dst_ip)
                    rules.append((dst_ip,create_rule_flow(flow,UDP_FLOOD),attack_type))

            # TCP syn flood
            elif (flow.get('protocol') == 'tcp' and flow.get('flags').get('syn') == 1):
                attack_type = 'TCP_SYN_FLOOD_'+str(flow.get('dst_ports').keys()[0])
                logger.info('Detect TCP syn flood to %s:%d',dst_ip,flow.get('dst_ports').keys()[0])
                rules.append((dst_ip,create_rule_flow(flow,TCP_SYN_FLOOD),attack_type))
            else:
                logger.info('Unknown attack %s:%d %d',dst_ip,flow.get('dst_ports').keys()[0],flow.get('src_ports').keys()[0])
                continue

        if (bps > config.FLOW_BAN_BPS):
            logger.info('Detect HUGE traffic flood (%d) to %s. BLACKHOLE it',bps,dst_ip)
            rules.append((dst_ip,create_rule_blackhole(flow),attack_type))
            continue

    return rules
