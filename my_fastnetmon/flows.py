__all__ = ['process_details','process_flows','process_unban','process_ban']

import re
import logging
import os
import my_fastnetmon.exabgp as exabgp
import my_fastnetmon.config as config

logger = logging.getLogger("log")

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
    return flow

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
    flows[key] = flow
    return flows

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

def create_rule_flow(flow,attack_type):
    rule = []
    rule.extend(('flow','route','destination',flow.get('dst_ip')+'/32'))
    if (attack_type == 'GRE_FLOOD'):
        rule.extend(('protocol','[ gre ]'))
    elif (attack_type == 'UDP_FLOOD'):
        rule.extend(('protocol','[ udp ]'))
        rule.extend(('source-port','[ ='+str(flow.get('src_ports').keys()[0])+' ]'))
    elif (attack_type == 'DNS_FLOOD'):
        rule.extend(('protocol','[ udp ]'))
        rule.extend(('source-port','[ ='+str(flow.get('src_ports').keys()[0])+' ]'))
        rule.extend(('packet-length','[ >900 ]'))
    elif (attack_type == 'TCP_SYN_FLOOD'):
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


def process_flows(flows):
    rules = []
    for key,flow in flows.items():
        if (flow.get('packets') > config.FLOW_BAN_PPS):
            # GRE proto (src and dst port == 0)
            if (flow.get('src_ports').get(0) == 1 and flow.get('dst_ports').get(0) == 1):
                logger.info('Detect GRE flood to %s',flow.get('dst_ip'))
                rules.append((flow.get('dst_ip'),create_rule_flow(flow,'GRE_FLOOD')))
                rules.append((flow.get('dst_ip'),create_rule_flow(flow,'UDP_FLOOD')))
            # UDP flood
            elif (flow.get('protocol') == 'udp' and len(flow.get('src_ports')) == 1):
                logger.info('Detect UDP flood from port %d to %s',flow.get('src_ports').keys()[0],flow.get('dst_ip'))
                # DNS UDP flood set minimum packet len
                if flow.get('src_ports').get(53) == 1:
                    logger.info('Detect UDP DNS flood to %s',flow.get('dst_ip'))
                    rules.append((flow.get('dst_ip'),create_rule_flow(flow,'DNS_FLOOD')))
                else:
                    rules.append((flow.get('dst_ip'),create_rule_flow(flow,'UDP_FLOOD')))

            # TCP syn flood
            elif (flow.get('protocol') == 'tcp' and flow.get('flags').get('syn') == 1):
                logger.info('Detect TCP syn flood to %s:%d',flow.get('dst_ip'),flow.get('dst_ports').keys()[0])
                rules.append((flow.get('dst_ip'),create_rule_flow(flow,'TCP_SYN_FLOOD')))
            else:
                logger.info('Unknown attack %s:%d %d',flow.get('dst_ip'),flow.get('dst_ports').keys()[0],flow.get('src_ports').keys()[0])
                continue
    return rules

def process_ban(rules):
    for (ip,rule) in rules:
        logger.info("Process BAN ip:%s with:'%s'",ip,rule)
        try:
            f = open(config.DATA_DIR+'/'+config.BAN_FILENAME+ip,"a+")
            f.write(rule+"\n")
            if (not config.EXABGP_DRYMODE):
                exabgp.send_command('announce '+rule)
            f.close()
        except (OSError, IOError) as err:
            logger.error("File error:%s",err)
    return

def process_unban(ip):
    try:
        f = open(config.DATA_DIR+'/'+config.BAN_FILENAME+ip,"r")
        for rule in f.readlines():
            logger.info("Process UNBAN ip:%s with:'%s'",ip,rule.strip())
            if (not config.EXABGP_DRYMODE):
                exabgp.send_command('withdraw '+rule.strip())
        f.close()
        os.remove(config.DATA_DIR+'/'+config.BAN_FILENAME+ip)
    except (OSError, IOError) as err:
        logger.error("File error:%s",err)
    return
