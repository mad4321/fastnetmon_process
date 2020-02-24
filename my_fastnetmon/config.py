import logging

program_name='process_attack'
program_version='1.1'

HOME_DIR = '/var/log/fastnetmon_attacks'

LOG_FILE  = HOME_DIR+'/attack_dev.log'
LOG_FILE  = '/dev/stdout'
LOG_LEVEL = logging.DEBUG

EXABGP_PIPE='/tmp/exabgp_flow.cmd'
EXABGP_DRYMODE = True

FLOW_COMMUNITY = '6768:9990'
DATA_DIR = HOME_DIR
BAN_FILENAME = 'ban_rule_ip_'

FLOW_BAN_PPS = 100000

SQLITE_DB = HOME_DIR+'/process_attack.db'

