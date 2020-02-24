#!/bin/sh
#91.241.166.211_19_02_20_16:21:28
#31.135.177.10_19_02_20_14:48:03 false
#31.135.177.1_18_02_20_20:40:25 udp & tcp
#31.135.177.200_18_02_20_20:18:28 syn

#LOGS=/var/log/fastnetmon_attacks/*_02_20*
#for log in $LOGS
#do
#  echo "Processing $log file..."
#  cat $log | ./process_attack.py 91.241.166.211 incoming 111111 attack_details
#done

#exit 0

#ban ip 
#cat /var/log/fastnetmon_attacks/91.241.166.26_23_02_20_11:32:35 | ./process_attack.py 91.241.166.92 incoming 111111 attack_details

#sleep 1
#unban ip 
cat /var/log/fastnetmon_attacks/91.241.166.92_21_02_20_10:58:12 | ./process_attack.py 91.241.166.26 incoming 111111 unban
