__all__ = ['process_unban','process_ban']

import re
import logging
import os
import sqlite3
from datetime import datetime

import my_fastnetmon.exabgp as exabgp
import my_fastnetmon.config as config
from my_fastnetmon.database import *

logger = logging.getLogger("log")

#
# process flowspec rules in exabgp
#
def process_ban(ip,rules):
    if not rules:
        return 1
    for (ip,rule,attack_type) in rules:
        logger.info("Process BAN ip:%s with:'%s'",ip,rule)
        if (not config.get('EXABGP_DRYMODE')):
            exabgp.send_command('announce '+rule)
        store_attack_host(ip,'',attack_type,rule)
    return 0

#
# remove all rules for <ip> from exabgp
#
def process_unban(ip):
    rules = get_attack_host(ip)
    remove_attack_host(ip)
    if not rules:
        return 1
    for (rule,) in rules:
        rule_count = get_attack_rules_count(rule)
        if (rule_count == 0):
            logger.info("Process UNBAN ip:%s with:'%s'",ip,rule)
            if (not config.get('EXABGP_DRYMODE')):
                exabgp.send_command('withdraw '+rule)
        else:
            logger.info("There is another BAN rule '%s' for %s network",rule,ip)
    return 0

