#!/bin/bash

###############################################################################
# This script is to disable the Te logs and collect them on conditional basis #
###############################################################################

nodeName="$1"
userName="$2"
password="$3"
isCloud="$4"
privateKeyPath="$5"
scenario="$6"

disable_TE_LOG_script_file="/var/tmp/disable_te_log.sh"

## Preparing the mo commands for disabling the Te logs on node

rm -rf $disable_TE_LOG_script_file
(
cat <<'END_AMOS'
#!/usr/bin/bash

nodeName="$1"
scenario="$2"
CURRENT_USER=`/usr/bin/whoami`

###Debug Mode
debug_file="/var/log/${CURRENT_USER}_disable_TE_script_debug_output.txt"
rm -rf $debug_file
exec 5>  $debug_file
BASH_XTRACEFD="5"
PS4='$LINENO: '
set -x

/bin/mkdir -p "/var/tmp/${CURRENT_USER}"

disable_te_log_command_file="/var/tmp/${CURRENT_USER}/disable_TE_LOGS.mo"
rm -rf "$disable_te_log_command_file"
(
cat <<'END_DISABLE_LOG'
dumpcap -Q
tm -status
tm -disconnect
ls -lrt /d/usr/cello/telogs/
ftget /d/logfiles/sniffer/default
ftget /d/usr/cello/telogs

END_DISABLE_LOG
) > $disable_te_log_command_file
chmod 777 $disable_te_log_command_file

folder_name=`echo "/var/tmp/${nodeName}_TE_LOGS_DUMPS_$(date +%Y_%m_%d_%H_%M_%S)_${scenario}"`
/bin/mkdir -p "$folder_name"
cd "$folder_name"
rm -rf "$folder_name"/*
/opt/ericsson/amos/bin/amos "$nodeName" "run $disable_te_log_command_file"
rm -rf "$disable_te_log_command_file" 

END_AMOS
) > $disable_TE_LOG_script_file 
chmod 777 $disable_TE_LOG_script_file

if [ $isCloud == "true" ]
then
   echo in cloud
   amos_ip=(`sudo consul members | grep amos`)
else
   echo not in cloud
   amos_ip=(`cat /etc/hosts | grep -i amos`)
fi


##deletes the 3 days (4320 mins) older logs in /var/tmp/
find /var/tmp/*TE_LOGS_DUMPS* -type d -mmin +4320 | xargs rm -rf

/usr/bin/expect -c "set timeout 2 ; spawn sh -c \"ssh -i $privateKeyPath cloud-user@${amos_ip[0]} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no sudo rm -rf /var/tmp/${nodeName}_*\" ;interact"

/usr/bin/expect -c "set timeout 2 ; spawn sh -c \"ssh ${userName}@${amos_ip[0]} bash -s -- < $disable_TE_LOG_script_file $nodeName $scenario\" ; expect ailure {send "yes\\r"} ; expect es/no {send "yes\\r"} ; expect "*?assword:" {send "${password}\\r"} ;  send "bash\\r" ; send "clear\\r" ;interact"

/usr/bin/expect -c "set timeout 2 ; spawn scp -r -i $privateKeyPath ${userName}@${amos_ip[0]}:/var/tmp/${nodeName}_TE_LOGS_DUMPS_* /var/tmp ; expect ailure {send "yes\\r"} ; expect es/no {send "yes\\r"} ; expect "*?assword:" {send "${password}\\r"} ;  send "bash\\r" ; send "clear\\r" ;interact"

rm -rf $disable_TE_LOG_script_file
rm -rf /var/tmp/te_logs_scripts

echo "############ TE_logs are disabled successfully on the node : $nodeName"

exit 0
