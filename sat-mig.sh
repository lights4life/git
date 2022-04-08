#!/bin/bash -xv

# SATELLITE Server INFO: pose02lx0150v.prod.sdt.ericsson.se / 172.29.36.180

# If curl gets failed. marked server as "no connectivity". don't proceed any other steps.
# If curl gets succeds. If step 1 got succeed. go for next steps. 
# Make a copy of all repo present in yum.repos.d directory.

echo "yes" | cp -prf /tmp/yum.repos.d/*.repo /etc/yum.repos.d/
cat /etc/*release*
printf "\n\n\n ################## Verify Satellite PORT is OPEN ######################\n"
echo quit | timeout --signal=9 3 telnet 172.29.36.180 443 > telnet_out.txt 2>&1
cat telnet_out.txt

export PATH=/bin:/usr/bin:/sbin:/usr/sbin:$PATH
OS_Name=`cat /etc/redhat-release | awk -F" " '{ print $1 }'`
OS_Version=`cat /etc/redhat-release | awk -F'[^0-9]+' '/[0-9]/ { print ($1 != "" ? $1 : $2) }'`
server_name=`hostname`

cat /etc/*release*
# CentsOS   <----->   echo 'proxy=http://www-proxy.ericsson.se:8080' >> /etc/yum.conf
[[ ${OS_Name} == CentOS ]] && { printf "HOSTNAME: %s, OSName: %s, OSversion: %s\n" "$server_name" "$OS_Name" "$OS_Version"; exit 1; }
[[ ${OS_Name} == Ubuntu ]] && { printf "HOSTNAME: %s, OSName: %s, OSversion: %s\n" "$server_name" "$OS_Name" "$OS_Version"; exit 1; }
[[ ${OS_Version} == 4 ]] && { printf "HOSTNAME: %s, OSName: %s, OSversion: %s\n" "$server_name" "$OS_Name" "$OS_Version"; exit 1; }
[[ ${OS_Version} == 5 ]] && { printf "HOSTNAME: %s, OSName: %s, OSversion: %s\n" "$server_name" "$OS_Name" "$OS_Version"; exit 1; }

# NSLOOKUP# /etc/hosts# 172.29.36.180 pose02lx0150v pose02lx0150v.prod.sdt.ericsson.se
#Step:1 - Download Satellite bootstrap from REMOTE Server to LOCAL Server
printf "####>>>> Step:1 - Download Satellite bootstrap from REMOTE Server to LOCAL Server.\n"
unset http_proxy; unset https_proxy
#curl -vvv -m 10 --noproxy -k "https://pose02lx0150v.prod.sdt.ericsson.se/pub/bootstrap.py" --output "/var/tmp/bootstrap.py"
#[[  $? == 0 ]] || wget -vvv --no-proxy --no-check-certificate -P /var/tmp https://pose02lx0150v.prod.sdt.ericsson.se/pub/bootstrap.py
curl --verbose --header -m 10 --noproxy -k "https://172.29.36.180/pub/bootstrap.py" --output "/var/tmp/bootstrap.py"
[[  $? == 0 ]] || wget -vvv --no-proxy --no-check-certificate -P /var/tmp https://172.29.36.180/pub/bootstrap.py

if [ $? == 0 ] ; then
#Step:2 - Clean up before running the Satellite bootstrap
printf "####>>>> Step:2 - Clean up before running the Satellite bootstrap.\n"
echo "yes" | cp -prf /etc/yum.repos.d /var/tmp
echo "yes" | rm -f /etc/yum.repos.d/*redhat*.repo
echo "yes" | rm -f /etc/yum.repos.d/*rhel*.repo
echo "yes" | rm -f /etc/yum.repos.d/*epel*.repo
echo "yes" | rm -rf /tmp/yum.repos.d; mkdir /tmp/yum.repos.d; mv /etc/yum.repos.d/*.repo /tmp/yum.repos.d/
echo "yes" | mv -f /etc/sysconfig/rhn/systemid /var/tmp
subscription-manager unsubscribe --all
subscription-manager remove --all
subscription-manager clean
chmod +x /var/tmp/bootstrap.py

#Step:3 - Run the Satellite Bootstrap
printf "####>>>> Step:3 - Run the Satellite Bootstrap.\n"
([ ${OS_Version} == 7 ] && (
/var/tmp/bootstrap.py --location="Sweden" --hostgroup="Default_Host_Group" --organization="Default_Organization" --activationkey="bmas_sdap_sca_rhel7_prod" --server pose02lx0150v.prod.sdt.ericsson.se --content-only --force) )

([ ${OS_Version} == 6 ] && (
/var/tmp/bootstrap.py --location="Sweden" --hostgroup="Default_Host_Group" --organization="Default_Organization" --activationkey="bmas_sdap_sca_rhel6" --server pose02lx0150v.prod.sdt.ericsson.se --content-only --force) )

#TROUBLESHOOTING STEPS - To Enable Satellite Registration & REPOS
#subscription-manager register --org="Default_Organization" --activationkey="bmas_sdap_sca_rhel7_prod"
#subscription-manager list --consum
#subscription-manager attach --auto
#subscription-manager refresh
#subscription-manager config

#Step:4 - Enable Satellite REPOS
printf "####>>>> Step:4 - Enable Satellite REPOS.\n"
([ ${OS_Version} == 7 ] && (
subscription-manager repos --enable=rhel-7-server-rpms
subscription-manager repos --enable=rhel-7-server-extras-rpms
subscription-manager repos --enable=rhel-7-server-satellite-tools-6.7-rpms) )

([ ${OS_Version} == 6 ] && (
subscription-manager repos --enable=rhel-6-server-rpms
subscription-manager repos --enable=rhel-6-server-extras-rpms
subscription-manager repos --enable=rhel-6-server-supplementary-rpms
subscription-manager repos --enable=rhel-6-server-satellite-tools-6.7-rpms) )

#Step:5 - Install Katello Agent
printf "####>>>> Step:5 - Install Katello Agent.\n"
yum --disablerepo=* --enablerepo=rhel* install katello-agent -y
if [ $? == 0 ] ; then
#Step:6 - Ensure redhat.repo is removed from  yum.repos.d directory.
yum --disablerepo=* --enablerepo=rhel* repolist
printf "================================================================"
printf "================================================================"
printf "\n\nHOSTNAME- %s, MIGRATION to Satellite COMPLETED.\n\n" "$server_name"
printf "================================================================"
printf "================================================================"

else 
printf "================================================================"
printf "================================================================"
printf "\n\nHOSTNAME- %s, MIGRATION to Satellite having issues, BELOW IS THE ERROR MESSAGE and make sure to mention this ERROR in the REPORT for the REFERENCE.\n\n" "$server_name"
yum --disablerepo=* --enablerepo=rhel* install katello-agent -y | head -20
printf "================================================================"
printf "================================================================"

fi

else
printf "================================================================"
printf "================================================================"
printf "\n\nHOSTNAME- %s, NO CONNECTIVITY and CURL FAILED.\n\n" "$server_name"
printf "================================================================"
printf "================================================================"

fi

echo "yes" | cp -prf /tmp/yum.repos.d/*.repo /etc/yum.repos.d/
cat /etc/*release*
printf "\n\n\n ################## Verify Satellite PORT is OPEN ######################\n"
echo quit | timeout --signal=9 3 telnet 172.29.36.180 443 > telnet_out.txt 2>&1
cat telnet_out.txt