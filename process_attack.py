#!/usr/bin/env python

import re
import socket,struct
import logging
import sys,getopt
import sqlite3

import my_fastnetmon.config as config

from my_fastnetmon.flows import *
from my_fastnetmon.flowspec import *
from my_fastnetmon.flowban import *
from my_fastnetmon.exabgp import *
from my_fastnetmon.database import *

logger = logging.getLogger("log")
logger.setLevel(config.LOG_LEVEL)
formatter = logging.Formatter("%(asctime)s - [%(process)d]:%(levelname)s:%(filename)s:%(funcName)s:%(lineno)d - %(message)s")
handler = logging.FileHandler(config.LOG_FILE)
handler.setFormatter(formatter)
logger.addHandler(handler)

if __name__ == '__main__':

    init_db()

    if len(sys.argv)<5:
        sys.exit(2)

    attack_ip = sys.argv[1]
    attack_dir = sys.argv[2]
    attack_pps = sys.argv[3]
    attack_action = sys.argv[4]
    logger.debug("Process %s for %s",attack_action,attack_ip)

    if (attack_action == "attack_details"):
        (main,flows) = process_details(sys.stdin.readlines())
        rules = process_flows(flows)
        process_ban(attack_ip,rules)
        exit(0)

    if (attack_action == "ban"):
        exit(0)

    if (attack_action == "unban"):
        process_unban(attack_ip)
        exit(0)

    exit(0);

exit(1)

