#!/usr/bin/env python

import os,sys,sqlite3,json

import my_fastnetmon.config as config
from my_fastnetmon.database import *

if __name__ == '__main__':
    init_db()
    ip_list = get_all_bans()
    result = {'data':[]}
    for (ip,) in ip_list:
        result['data'].append({'{#BAN_IP}':ip})

    if len(sys.argv)>1:
        check_ip = sys.argv[1]
    else:
        check_ip = ''
#    result['data'].append({'{#BAN_IP}':'10.10.10.1'})
#    result['data'].append({'{#BAN_IP}':'10.10.10.2'})
    if check_ip:
        for ip in [v.values() for v in result['data']]:
            if (ip[0] == check_ip):
                print ("1")
                sys.exit(0)
        print ("0")
    else:
        print json.dumps(result)
    sys.exit(0);

sys.exit(1)

