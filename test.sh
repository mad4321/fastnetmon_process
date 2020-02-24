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
#91.241.166.211_23_02_20_10:19:31
#91.241.166.40_23_02_20_10:19:51
#91.241.166.60_23_02_20_10:20:51
#91.241.166.60_23_02_20_10:51:18
#91.241.166.27_23_02_20_11:27:49
#91.241.166.25_23_02_20_11:32:35
#91.241.166.26_23_02_20_11:32:35
cat /var/log/fastnetmon_attacks/91.241.166.211_24_02_20_08:45:35 | ./process_attack.py 91.241.166.92 incoming 111111 attack_details
cat /var/log/fastnetmon_attacks/91.241.166.6_24_02_20_11:34:44 | ./process_attack.py 91.241.166.92 incoming 111111 attack_details

sleep 1
#unban ip 
./process_attack.py 91.241.166.211 incoming 111111 unban
sleep 1
./process_attack.py 91.241.166.6 incoming 111111 unban
