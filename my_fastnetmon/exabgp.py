__all__ = ['send_command']

import logging
import my_fastnetmon.config as config

logger = logging.getLogger("log")

def send_command(rule):
    try:
        f = open(config.get('EXABGP_PIPE'),"w")
        f.write(rule+"\n")
        f.close()
        return 0
    except (OSError, IOError) as err:
        logging.error('File error: %s',err)
        return 1

