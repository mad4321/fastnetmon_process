import logging

program_name='process_attack'
program_version='1.0'

LOG_FILE  = '/var/log/fastnetmon_attacks/attack.log'
#LOG_FILE  = '/dev/stdout'
LOG_LEVEL = logging.DEBUG

EXABGP_PIPE='/tmp/exabgp_flow.cmd'
EXABGP_DRYMODE = False
#EXABGP_DRYMODE = True

FLOW_COMMUNITY = '6768:9990'
DATA_DIR = '/var/log/fastnetmon_attacks'
BAN_FILENAME = 'ban_rule_ip_'

FLOW_BAN_PPS = 100000
