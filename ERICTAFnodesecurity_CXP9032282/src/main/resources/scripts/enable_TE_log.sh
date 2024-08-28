#!/bin/bash

nodeName="$1"
userName="$2"
password="$3"
isCloud="$4"

enable_TE_LOG_script_file="/var/tmp/enable_te_log.sh"

## Preparing the mo commands for enabling the Te logs on node

rm -rf $enable_TE_LOG_script_file
(
cat <<'END_AMOS'
#!/usr/bin/bash

CURRENT_USER=`/usr/bin/whoami`

###Debug Mode
debug_file="/var/log/${CURRENT_USER}_enable_TE_script_debug_output.txt"
rm -rf $debug_file
exec 5>  $debug_file
BASH_XTRACEFD="5"
PS4='$LINENO: '
set -x

_RM_RF="/bin/rm -rf "
nodeName="$1"


/bin/mkdir -p "/var/tmp/${CURRENT_USER}"
enable_te_log_command_file="/var/tmp/${CURRENT_USER}/enable_TE_LOGS.mo"

$_RM_RF $enable_te_log_command_file
(
cat <<'END_ENABLE_LOG'
csti info
te default *
te save *
te e all CPPSEC_PKIMGMT_IF
te e all cppsec_pkimgmt_ctrl
te e all cppsec_pkimgmt_server
te d trace3 cppsec_pkimgmt_server
te d trace3 cppsec_pkimgmt_ctrl
te preset trace1 trace2 trace9 enter return send_sig rec_sig cppsec_c*
te preset trace1 trace2 trace9 enter return send_sig rec_sig cppsec_s*
te preset trace1 trace2 trace9 enter return send_sig rec_sig cppsec_m*

te e all Ipi_ipsecfh_proc
te e all IPSECFH_MODATA
te e all IPSECFH_DOMAIN
te e trace5 se.ericsson.cello.moframework.NotificationSender:*
te preset trace1 trace9 cppsec_cmpClient

te save *

readclock
tm -disconnect
ls -lrt /d/usr/cello/telogs/
tm -disk activate
tm -attach 12 COREMPBOARDVALUE
tm -save
tm -disk ls
tm -status
ls -lrt /d/usr/cello/telogs/
dumpcap -o -a duration:3600 -i any

END_ENABLE_LOG
) > $enable_te_log_command_file
chmod 777 "$enable_te_log_command_file"


FetchAndAppendCorempBoardValue(){
local -r defaultVal="000100"
local -r tmpFile="/tmp/$$_fetchNum"
rm -rf "$tmpFile"
/opt/ericsson/amos/bin/amos "$nodeName" "bp coremp"> "$tmpFile"
corempVal=($(cat "$tmpFile"|grep " coremp "|awk '{print $1}'))
finalVal=`echo ${corempVal[@]}`
if [[ $finalVal == "" || ! $finalVal =~ ^\ |[0-9]+$ ]]; then
finalVal=$defaultVal
fi
rm -rf "$tmpFile"
/bin/sed -i "s/COREMPBOARDVALUE/$finalVal/g" "$enable_te_log_command_file";
}

FetchAndAppendCorempBoardValue
/opt/ericsson/amos/bin/amos "$nodeName" "run $enable_te_log_command_file"
$_RM_RF "$enable_te_log_command_file"

END_AMOS
) > $enable_TE_LOG_script_file 
chmod 777 $enable_TE_LOG_script_file

if [ $isCloud == "true" ]
then
   echo in cloud
   amos_ip=(`sudo consul members | grep amos`)
else
   echo not in cloud
   amos_ip=(`cat /etc/hosts | grep -i amos`)
fi


/usr/bin/expect -c "set timeout 2 ; spawn sh -c \"ssh ${userName}@${amos_ip[0]} bash -s -- < $enable_TE_LOG_script_file $nodeName\" ; expect ailure {send "yes\\r"} ; expect es/no {send "yes\\r"} ; expect "*?assword:" {send "${password}\\r"} ;  send "bash\\r" ; send "clear\\r" ;interact"

rm -rf $enable_TE_LOG_script_file

echo "############ TE_logs are enabled successfully on the node : $nodeName"
exit 0

