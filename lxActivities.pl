0**##########################################################
0****SSM->Incident_Management->Search_Incident->Advanced_Search------->with_Below_RULE.
('Incident Type*'="User Service Restoration" OR 'Incident Type*'="User Service Request") AND 'Status*'<4 AND ('Assigned Group*+'="P&S-PLATFORM-L2")

0****##########################################################
0****Out_of_Memory (OOM)
# Out of Memory (OOM) refers to a state where all available memory, including swap space, has been allocated.
# Normally this will cause the system to panic and stop functioning as expected. 
# There is a switch that controls OOM behavior in /proc/sys/vm/panic_on_oom
# The default setting is 0 which instructs the kernel to call a function named oom_killer on an OOM, Usually, oom_killer can kill rogue processes and the system will survive.
# When set to 1 the kernel will panic on OOM.
echo 0 > /proc/sys/vm/panic_on_oom    /# KERNEL will not PANIC & oom_killer can kill rogue processes and the system will survive.
echo 1 > /proc/sys/vm/panic_on_oom    /# KERNEL will PANIC, when OOM occurs.

# Linux provides a way to enable and disable the OOM-Killer, but it is recommended to enable the OOM-killer. 
# Kernel parameter vm.oom-kill is used to enable and disable the OOM-Killer. 
# If you want to enable OOM-Killer runtime, then use sysctl command to enable that.sudo -s sysctl -w vm.oom-kill = 1
sysctl -w vm.oom-kill = 1   				# ENABLE OOM-Killer
sysctl -w vm.panic_on_oom = 0		# KERNEL will not PANIC, when OOM occurs.

# This command does not set that permanently, and a machine reboot resets that. To set it permanently, add this line in /etc/sysctl.conf file:
echo vm.oom_kill_allocating_task = 1 >>/etc/sysctl.conf
echo vm.oom-kill = 1 >>/etc/sysctl.conf
echo vm.panic_on_oom = 0 >>/etc/sysctl.conf
sysctl -p /etc/sysctl.conf

0****##########################################################
0****find_command
# how to find pattern in whole file system.
find /var -xdev -type f -print0 | xargs -0 grep -H "172.29.51.6"
#/

0****##########################################################
0****KVM_VIRSH
virsh vol-info ldprvmit12.qcow2 --pool vmimages
virsh pool-list
virsh pool-info vmimages
[root@ldprpmit01 qemu]# virsh domblklist ldprvmit12
Target     Source
------------------------------------------------
vda        /vmimages/ldprvmit12.qcow2
hda        -
[root@ldprpmit01 qemu]# virsh dumpxml ldprvmit12 | egrep 'disk type' -A 5
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/vmimages/ldprvmit12.qcow2'/>
      <backingStore/>
      <target dev='vda' bus='virtio'/>
      <boot order='1'/>
--
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <backingStore/>
      <target dev='hda' bus='ide'/>
      <readonly/>
      <boot order='2'/>
[root@ldprpmit01 qemu]# qemu-img info  /vmimages/ldprvmit12.qcow2
[root@ldprpmit01 qemu]# virsh snapshot-info --domain ldprvmit12 --current
[root@ldprpmit01 qemu]# virsh snapshot-delete --domain ldprvmit12 --snapshotname snapshot1

0****##########################################################
0****GCP
# To resolve yum check-update issue
# Before Activity
systemctl stop google-osconfig-agent
systemctl status google-osconfig-agent
# After Activity
systemctl start google-osconfig-agent
systemctl status google-osconfig-agent

0****##########################################################
0****telnet
sleep 1 | telnet 35.164.23.230 443 >> telnet_out.txt 2>&1

0****##########################################################
0****sos_report_Redhat
#Attach the sosreport to the case:
redhat-support-tool addattachment -c 03179645 /path/to/sosreport


0****##########################################################
0****_NFS_ACL
I do not see any domain mapped on this client.
$ grep -i "domain =" /etc/idmapd.conf
##Domain = local.domain.edu            
Additionally, I can see that ID mapping is disabled on this client. So, this is what's intended.

$ cat sys/module/nfs/parameters/nfs4_disable_idmapping                     
Y

Before we try to set any ACL over NFS we need to ensure the following:
ACLs must be enabled at NAS server.
required packages must be installed on the client.
domain must be mapped on the client as of the server.
If NFSv4 idmapping is intended to be disabled in the configuration, then the UIDs/GIDs must match on the NFS server and NFS client.

From the previous set of data, we can see EVERYONE already has rwx access. So, there isn't a need to provide it again.

[root@pose01lx0210v ~]#  /Enableshare/
# file: /Enableshare/
A::OWNER@:rwaDdxtTnNcCoy
A:g:GROUP@:rwaDdxtTnNcCoy
A::EVERYONE@:rwaDdxtTnNcCoy        <----------------------

Please understand that the default permissions for directories are 777 and for files it's 666, so even with ACL's any new directory which gets created will have 777 permissions whereas for files, it would be 666 only. This is considered as default permissions.
In order to change to 777 for files, that has to be done manually using some sort of script executed via a cron job from the client side. (provided the user has access)

However, as mentioned previously if you are looking to change the default permissions for all 'files' to 777 then this cannot be achieved via ACLs as well. This is what I believe your actual requirement is. Quoting the previous update:

0****##########################################################
0****_TCPDUMP
# -n, -nn...disable name resolution by using the option -n and port resolution with -nn
# -w...for writing output, -r...for reading the file
# -v,-vv for verbose
# -c....for no. of counts

#Follow below steps to collect the strace and tcpdump:-
tcpdump -s 0 -i any host <NFS_SERVER_IP> -w /tmp/tcpdump.pcap &

#Now reproduce the issue:-
strace -fvttTyyx -s 4096 -o /tmp/strace.txt touch test123

#Once the issue reproduced stop the tcpdump:-
pkill tcpdump

#sudo tcpdump -D
1.eth0
2.virbr0
3.eth1
4.any (Pseudo-device that captures on all interfaces)
5.lo [Loopback]

#Capture all packets in any interface by running this command:
$ sudo tcpdump -i any -w /tmp/tcpdump.out &

#capture ICMP packets only by using this command:
$ sudo tcpdump -i any -c5 icmp

#Limit capture to only packets related to a specific host by using the host filter:
$ sudo tcpdump -i any -c5 -nn host 54.204.39.132 port 80

#capture packets related to a web (HTTP) service by using this command:
$ sudo tcpdump -i any -c5 -nn port 80

#capture packets from source host 192.168.122.98:
$ sudo tcpdump -i any -c5 -nn src 192.168.122.98

#capture packets to any destination host 192.168.122.98:
$ sudo tcpdump -i any -c5 -nn dst 192.168.122.98

#filter packets from source IP address 192.168.122.98 and service HTTP only, use this command:
$ sudo tcpdump -i any -c5 -nn src 192.168.122.98 and port 80

$ sudo tcpdump -i any -c5 -nn "port 80 and (src 192.168.122.98 or src 54.204.39.132)"

awk '$3=="kB"{$2=$2/1024;$3="MB"} 1'

0****##########################################################
0****_large_files
# BEST ONE for finding LARGE FILES
#find /var -xdev -type f -exec du -Sh {} + | sort -rh | head -n 20
find / -xdev -type f -exec du -Sh {} + | sort -rh | head -n 20
find /var -xdev -type f -exec du -Sh {} + | sort -rh | head -n 20

# BEST ONE for finding LARGE Directories/Folders
du -ahx --max-depth=5 / | sort -rh | head -10
du -ahx --max-depth=5 /var | sort -rh | head -10
du -ahx --max-depth=5 /opt | sort -rh | head -10

# KB
find /var -xdev -type f -printf '%s %p\n'| sort -nr | head -20
# MB
find /var -xdev -type f -printf '%s %p\n'|sort -nr |head -20 |awk '{$1=$1/(1024*1024)} 1'
# GB
find /var -xdev -type f -printf '%s %p\n'|sort -nr |head -20 |awk '{$1=$1/(1024*1024*1024)} 1'

'0****##########################################################
0****_LVM_create
lsblk
lvmdiskscan
fdisk /dev/sda <<-EOF
p
n
t
p
w
EOF
pvcreate /dev/sdb1 /dev/sdc
vgcreate vg_name /dev/sdc /dev/sdn1
lvcreate -L 450 -n my_lv my_vg
mkfs.ext4 /dev/vg_name/lv_name
#/

0****##########################################################
0****_LVM_extend
pvcreate /dev/sdc
vgextend vg_name /dev/sdc /dev/sdn1
lvextend -l +100%FREE -r /dev/vg_name/lv_name
#/

0****##########################################################
0****_postfix
--> how to clear /var/spool/postfix/maildrop
#Any time cron runs a task where there is any failure, like a file or directory does not exist and the task (script) does not check for its existence before attempting to use it, cron will mail the owner of the task to indicate the failure. As postfix is not running, this causes the /var/spool/postfix/maildrop directory to fill with undelivered mail files, consuming an inode for every file. And there is no mechanism to automatically clean up the conversion. After a long time, this directory has accumulated a large number of small file

#1) Add MAILTO="" in the first line of crontab, so that when the current user's cron is executed, no mail will be sent.
sed -i '1 i\MAILTO=""' /var/spool/cron/root
#2) How to flush or delete emails from the postfix mail queue, this causes the /var/spool/postfix/maildrop directory to fill with undelivered mail files

# To flush the queue (force delivery) :****
postfix flush

# Check the mail queue, using the mailq command and delete a specific email like so :
postsuper -d <mailID>

# To remove all mail from all the queues ( hold, incoming, active and deferred ) , run :
postsuper -d ALL

# To remove all mails in the deferred queue only, run :
postsuper -d ALL deferred

# Test the existing Postfix configuration 
# Your current configuration may have errors without you even knowing. So let’s first test for that.
postconf 1> /dev/null

# Backup your Postfix configuration
tar czf /var/tmp/postfix-$(date "+%F").tar.gz /etc/postfix

# For later troubleshooting or comparing configurations, it is also wise to use postconf to store a copy.
postconf > /var/tmp/postconf-$(date "+%F")

# Disallow any methods that do allow anonymous authentication
smtp_sasl_security_options = noanonymous

### configuration 
Relay 	IP 	DC
smtp.int.se.nmc.ericsson.se	153.88.33.45/153.88.33.46  	Skondal
oselilx0001v.int.msdp.ericsson.se	172.29.36.24	Linkoping
osesalx0001v.int.msdp.ericsson.se	172.29.4.24	Akalla
ouspllx0001v.int.msdp.ericsson.se	172.29.68.24	Dallas Plano
ousaalx0001v.int.msdp.ericsson.se	172.29.100.24	New Jersey
oinnnolx0001v.int.msdp.ericsson.se	172.29.132.24	Noida
smtp.int.in.nmc.ericsson.se	150.236.127.50/150.236.127.51	Gurgaon
exchange-115-vip1.ss.sw.ericsson.se

# 153.88.115.51 / smtp-central.internal.ericsson.com
relayhost = smtp-central.internal.ericsson.com
relayhost = smtp.int.in.nmc.ericsson.se
relayhost = smtp.int.se.nmc.ericsson.se
myhostname = minnolx138v.bharatino.ext.in.nmc.ericsson.se
mydomain = ericsson.se [or] mydomain = ericsson.com
myorigin = $mydomain
inet_interfaces = $myhostname, 127.0.0.1, localhost
mydestination = $myhostname, localhost.$mydomain, localhost
mynetworks = 127.0.0.0/8, localhost, 172.0.0.0/8

##############################################################
### maximum message size in POSTFIX & SENDMAIL
### 35MB is the Message_Size_Limit by ERICSSON EXCHANGE GATEWAY 
### SENDMAIL
cp -p /etc/mail/sendmail.cf /etc/mail/sendmail.cf.27jan22.bkup
ls -ltr /etc/mail/sendmail.cf*
# maximum message size
O MaxMessageSize=35840000
# relayhost
DShostname.domain

### POSTFIX
postconf message_size_limit
cp -p /etc/postfix/main.cf /etc/postfix/main.cf.27jan22.bkup
message_size_limit = 35840000
 cat /etc/postfix/main.cf | egrep "^relayhost|^myhostname|^mydomain|^myorigin|^inet_interfaces|^mydestination"
##############################################################

########POSTFIX_CONFIG_AUTOMATION########################
cat /etc/postfix/main.cf | egrep "^relayhost|^myhostname|^mydomain|^myorigin|^inet_interfaces|^mydestination"
cp -p /etc/postfix/main.cf /etc/postfix/main.cf.bkup.`date +"%d-%b-%Y_%H-%M-%S"`

relayhost="smtp.int.se.nmc.ericsson.se"
myhostname="osekilx0521v.int.se.nmc.ericsson.se"
mydomain="ericsson.com"
myorigin="\$mydomain"
inet_interfaces="\$myhostname, 127.0.0.1, localhost"
mydestination="\$myhostname, localhost.\$mydomain, localhost"
#mynetworks = 127.0.0.0/8, localhost, 172.0.0.0/8


sed -i.bk -e "s/^relayhost.*/relayhost = "${relayhost}"/" /etc/postfix/main.cf
sed -i.bk -e "s/^myhostname.*/myhostname = "${myhostname}"/" /etc/postfix/main.cf
sed -i.bk -e "s/^mydomain.*/mydomain = "${mydomain}"/" /etc/postfix/main.cf
sed -i.bk -e "s/^myorigin.*/myorigin = ""${myorigin}""/" /etc/postfix/main.cf
sed -i.bk -e "s/^inet_interfaces.*/inet_interfaces = ""${inet_interfaces}""/" /etc/postfix/main.cf
sed -i.bk -e "s/^mydestination.*/mydestination = ""${mydestination}""/" /etc/postfix/main.cf

egrep "^relayhost|^myhostname|^mydomain|^myorigin|^inet_interfaces|^mydestination" /etc/postfix/main.cf

########POSTFIX_CONFIG_AUTOMATION########################

0****##########################################################
0****_AD_
gpmc.msc   #Group Policies
dsa.msc    #AD

#sudo issue, if sudo does not work in vasd
Defaults always_query_group_plugin

#/opt/quest/bin/vgptool apply  
pam_tally2 --user=username
pam_tally2 --user=username --reset

### VAS timesync/NTP
# If vasd detects NTP (by checking port 123 being bound) when it starts it completly skips all time synchronization, regardless of any timesync-interval setting.
# A reminder, VAS requires the client machines to be in sync with the DC.
# The main authentication method for VAS, Kerberos, is time sensitive, and usually requires clocks be within 5 minutes to function.
# You must use either the timesync from VAS or NTP to ensure that system clocks are synched.   This might otherwise impede VAS from working properly.
vasd when it starts, and by default every 12 hours, attempts to syncronize the time. 
=====>/etc/opt/quest/vas/vas.conf
[vasd]
 timesync-interval = 0   #Disables TimeSync via DC
 timesync-interval = 1   #Enables TimeSync via DC
#To correct a clock skew on the Unix host run
#This will synchronize the host's system clock to within 1 second of the Domain Controller for the domain the host is joined to.  
/opt/quest/bin/vastool timesync
//#

0****##########################################################
0****NTP
### NTP SYNC STATUS check
ntpq -pn

### Steps to force NTP sync
service ntpd stop
# Force an update:
# -g – requests an update irrespective of the time offset
# -q – requests the daemon to quit after updating the date from the ntp server.
ntpd -gq
service ntpd start

#RHEL7
date --set "4 Dec 2017 10:00:00"
systemctl stop ntpd
ntpdate <NTP_Server_IP>
systemctl start ntpd

### Recommended Configuration by Redhat:
•	It is NOT recommended to use only two NTP servers.
•	Four NTP servers is the recommended minimum. Four servers protect against one incorrect timesource, or "falseticker".
•	Use at least 4 NTP servers, Preferably use upstream NTP server.
•	Do not use a Virtual Server as NTP server: NTP server was not designed to run inside of a virtual machine. It requires a high resolution system clock, with response times to clock interrupts that are serviced with a high level of accuracy.

0****##########################################################
0****HPE_HPSG_HP_ServiceGuard_Cluster
###########################################
#Check logs:
cat /var/log/messages | grep -i cm

###########################################
# usage: cmviewcl [-v] [-f {table|line}] [-s config]
       [-l {package|cluster|node|group}] [-c cluster_name]
       {[-n node_name]... | [-p package_name]...}
	   
# Check complete CLUSTER STATUS
cmviewcl
cmviewcl -v

# Check Specific Node STATUS
cmviewcl -n <NodeName>
cmviewcl -v -n <NodeName>

# Check SPECIFIC PACKAGA STATUS on the NODE
cmviewcl -n <NodeName> -p <Pkg_Name>
cmviewcl -v -n <NodeName> -p <Pkg_Name>

##############################################
##############################################
# Enable PACKAGE to run on NODE <NodeName> [WORKS]
cmmodpkg -e -v -n <NodeName> <Pkg_Name>

# RUN PACKAGE on the Current Node. [WORKS]
cmrunpkg wfm_dbcluster2_PRDWFMSO_pkg

# Enable AUTO_RUN for PACKAGE on Current Node.
# exclude -n to affect global switching [WORKS]
cmmodpkg -e <Pkg_Name>
# include -n to affect node_switching
cmmodpkg -e -n <NodeName> <Pkg_Name> 
##############################################
##############################################

##############################################
Fail over without halting clustering on either node:
1. cmviewcl –v (This will display status packages and nodes defined to cluster. Verify
status of nodes and pkgs before taking any action.)
2. cmhaltpkg –n <nodename> –v <pkgname> (command can be issued from either node;
if node name not specified, command will be executed on whichever node it is issued
from)
3. Wait to see results of command; tail –f /etc/cmcluster/<pkgname>.cntl.log to determine
success or failure of halt command. If successful, move on to step 3.
4. cmmodpkg –e –n <nodename> -v <pkgname> (enables pkg to run, and enables pkg
switching. This can be issued on either node. It will automatically start pkg on it’s
adoptive node if nodename is not specified)
5. cmrunpkg –n <nodename> -v <pkgname> (starts specified pkg on specified node. Can
be run from either node.
##############################################

##############################################
What are the daemons that control MC/Serviceguard

There are the OS MC ServiceGurard Components, and the Application Packages. Eight Daemons are associated with MC/ServiceGuard.

/usr/lbin/cmclconfd---ServiceGuard Configuration Daemon
/usr/lbin/cmcld---ServiceGuard Cluster Daemon
/usr/lbin/cmlogd---ServiceGuard Syslog Log Daemon
/usr/lbin/cmlvmd---Cluster Logical Volume Manager Daemon
/usr/lbin/cmomd---Cluster Object Manager Daemon - logs to /var/opt/cmom/cmomd.log
/usr/lbin/cmsnmpd---Cluster SNMP subagent (optionally running)
/usr/lbin/cmsrvassistd---ServiceGuard Service Assistant Daemon
/usr/lbin/cmtaped---ServiceGuard Shared Tape Daemon
Each of these daemons logs to the /var/adm/syslog/syslog.log file
##############################################

###########################################
#HPSG: oracle service status check scripts path on server:
/usr/local/cmcluster/oracletoolkit/
-r-xr-xr-x 1 root root  5086 Jun  6  2012 hadbhang.mon
-r-xr-xr-x 1 root root  1578 Jun  6  2012 hagetdbstatus.sh
-r-xr-xr-x 1 root root  1497 Jun  6  2012 hatimeoutdbhang.sh
 ###########################################
0****##########################################################
0****NTP_Chrony
timedatectl set-ntp true
cat /etc/chrony.conf | grep -v "^#" | awk 'NF'
systemctl status chronyd
timedatectl
chronyc tracking
chronyc sources
chronyc sourcestats

#Just like ntpdate command in NTP distribution, we can use chronyd to sync time of our Linux server with remote NTP server manually.
# chronyd -q ‘server {ntp_server_name} iburst’  
chronyd -q 'server 10.32.4.14 iburst'


0000****##########################################################
0****Chrony
timedatectl set-ntp true
cat /etc/chrony.conf | grep -v "^#" | awk 'NF'
systemctl status chronyd
timedatectl
chronyc tracking
chronyc sources
chronyc sourcestats

0000****##########################################################
0****Local_USER_Access
# The only thing is this needs a pre-encrypted password string which you'd have to generate first.
usermod --password PASSWORD USERNAME
I# In order to generate the encrypted password you can use openssl. For example:
usermod --password $(echo "MY_NEW_PASSWORD" | openssl passwd -1 -stdin) USERNAME
usermod --password $(echo "Welcome@12345" | openssl passwd -1 -stdin) eryvzah
# To force chage the password at login
passwd -e eryvzah

groupadd appuser
useradd  -g appuser -G wheel -c "AppUser"  -m eryvzah
echo "Welcome@12345" | passwd --stdin eryvzah
passwd -x -1 eryvzah

0****##########################################################
0****_To_Check_all_FS_in_fstab_mounted_df-h
FSinFsTab=`cat /etc/fstab|awk '{ print $2 }'`
for FSinDf in `echo $fstabFS`;do df -h ${FSinDf};done

0****##########################################################
0****_zombie_process
### find the zombies
ps xal | awk '{ print $3 " " $4 " " $10 " " $9 " " $13 }' | grep " Z"

### Killing Zombies
for i in `cat zombie.txt`; do 
zombiePPID=`ps xal | grep $i |egrep -v "grep|bogus"|awk '{ print $4 }'`
kill -9 $zombiePPID
done

0****##########################################################
0****_PERL_ONE_LINERS
perl -ne '/regex/ && print' file_name
perl -ne '/sareh.saremi\@ericsson.com/ && print' /var/log/maillog
perl -ne 's/ +/ /g && print' serverList.txt # Replace multi spaces with single space
perl -pi.bak -e 's/ +/ /g' serverList.txt # In-File Replace multi spaces with single space
perl -F"\t" -ane 'print $F[0] . "\n"' serverList1.txt # printing specific COLUMN
perl -F"\t" -ane 'print $F[0]'
perl -lanE '$,="\t"; say @F[0,1,3,5]' 1.txt 2.txt 3.txt

0****##########################################################
0****sed_commands
#Replace only on the first matching line with sed
sed -i.bk '1,/abc/s//xyz/' file.txt
sed -i -e 's/word1/word2/g' -e 's/xx/yy/g' input.file
sed -i "s/$var1/ZZ/g" "$file"
#If you've a lot shell meta-characters, consider using single quotes for the pattern, and double quotes for the variable:
sed -i 's,'"$pattern"',Say hurrah to &: \0/,' "$file"
sed -i.bk -e 's/HISTORY\=28/HISTORY\=30/g' /etc/sysconfig/sysstat

0****##########################################################
0****awk_sed_commands
awk -F" " '{ print $9 }' # Print specific column oe nth word in a row


0****##########################################################
0****_NetApp_Storage / scsi
/sbin/dmsetup info -c|grep -i one_tm_log
/sbin/multipath -l
/sbin/scsi_id -g -u -s /dev/sdbs
systool -c fc_host -v

ls -dl /sys/block/sd*/device/scsi_device/*
lsblk

/0****##########################################################
0****_ulimit
[root@example ~]# cat test.sh

### To check if user reached particular limit according to his ulimit configuration.
#!/bin/bash
#########################
username="user1"
appname="firefox"
#########################

open=`ulimit -Ha | grep -i open | cut -d' '  -f25`
process=`ulimit -Ha | grep -i process | cut -d' '  -f18`
echo -e "The limit for maximum number of processes is: $process"
echo -e "The limit for maximum number of files is: $open\n"

########## Number of open Process ###################
Tot_process=`ps hauxwwwm Ou | cut '-d ' -f1 | uniq -c | grep "$username" | sed "s/^[ \t]*//" |cut -d' ' -f1`
#echo "The Number of all open processes by $name user is: $Tot_process "
if [ ! -z "Tot_process" ]; then
  let Tot_process+=0
  if [ "$Tot_process" -gt "100" ]; then
    echo -e "$username: limit execeeded, current count is $Tot_process\n"
  fi
fi

############ To count Number of open files by a particular process ########
pid=`ps -C "$appname" -o pid=`
if [ ! -z "$pid" ]; then
  file=`lsof -p $pid |wc -l `
  let file+=1

  if [ "$file" -gt "200" ]; then
    echo "$appname: limit execeeded, current count is $file"
  fi
fi

The output of above script after executing would be:
[root@example ~]# ./test.sh 
The limit for maximum number of processes is: 5243
The limit for maximum number of files is: 4096
user1: limit execeeded, current count is 270
firefox: limit execeeded, current count is 217

0****##########################################################
0****_rsync
Although UID//GID and symlinks are preserved by -a (see -lpgo), your question implies you might want a full copy of the filesystem information; 
and -a doesn't include hard-links, extended attributes, or ACLs (on Linux)
Thus, for a robust copy of a filesystem, you'll need to include those flags:

# -avhz
rsync -aHAXvhzl –progress source dest # Linux

0****##########################################################
0****_top_CPU_consuming_processes
top -b -n 1 | head -20
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -20

0****##########################################################
0****_top_Memory_consuming_processes
### Cumilative memory taken by processes in "MB"
ps aux | grep syslog-ng | awk '{sum=sum+$6}; END {print sum/1024 " MB"}'
ps aux | grep syslog-ng | awk '{sum=sum+$6}; END {print sum/1024}'
### Sum of memory in number (in MB) of multiple process.
ps aux | grep syslog-ng | awk '{sum=sum+$6}; END {print sum/1024}' | awk -F  "." '{print $1}'

0****##########################################################
0****_syslog-ng troubleshooting
# syslog-ng syntax tool which allows for the verification of a valid syslog-ng configuration.
/opt/syslog-ng/sbin/syslog-ng -svf /opt/syslog-ng/etc/syslog-ng.conf

0****##########################################################
0****If_Memory_exceeds_then_restart_process.
Mem_SyslogNG=`ps aux | grep syslog-ng | awk '{sum=sum+$6}; END {print sum/1024}' | awk -F  "." '{print $1}'`
OS_Version=`cat /etc/redhat-release | awk -F'[^0-9]*' '/[0-9]/ { print ($1 != "" ? $1 : $2) }'`
[ $Mem_SyslogNG -gt 1 ] && [ ${OS_Version} == 7 ] && systemctl restart syslog-ng
[ $Mem_SyslogNG -gt 1 ] && [ ${OS_Version} != 7 ] && /sbin/service syslog-ng restart

### If SYSLOG-NG needs restart, then restart process.
OS_Version=`cat /etc/redhat-release | awk -F'[^0-9]*' '/[0-9]/ { print ($1 != "" ? $1 : $2) }'`
syslogNG_status=`systemctl status syslog-ng | grep -i "Active: active" | grep -v grep|wc -l`
[ $syslogNG_status -ne 1 ] && [ ${OS_Version} == 7 ] && systemctl restart syslog-ng

### 
OS_Version=`cat /etc/redhat-release | awk -F'[^0-9]*' '/[0-9]/ { print ($1 != "" ? $1 : $2) }'`
syslogNG_status=`systemctl status syslog-ng | grep -i "Reloading System Logger Daemon" | grep -v grep|wc -l`
[ $syslogNG_status -ge 1 ] && [ ${OS_Version} == 7 ] && systemctl restart syslog-ng



0****##########################################################
0****_stats
### I/O stats
sar -p -d 1 1

#Along with the above information I would like to get some informational tool outputs to see where we need to focus. One of these to start off with would be iostat. The iostat command is used for monitoring system input/output device loading by observing the time the devices are active in relation to their average transfer rates. The iostat command generates reports that can be used to change system configuration to better balance the input/output load between physical disks.
#During your *** time of most heavy load ***, I would ask that you open a separate terminal window and execute the following command:
iostat -Ntmx 1 | tee -a CASENUMBER-$(hostname)-iostat.txt

#This will show me how the system is handling IO and if we need to perform a bit of tuning. Please let this utility run for at least an hour if not more. Once the time has past, please stop this process and attached the resulting file for my analysis.

0****##########################################################
0****_logrotate
## Instead of waiting for the next cron job, you can use the following command to test that the modifications work:
Raw
logrotate -f /etc/logrotate.conf

logrotate -d /etc/logrotate.d/maillog

[root@osesalx0001v logrotate.d]# cat maillog
/var/log/maillog {
        daily
        copytruncate
		create 644 root root
        rotate 30
        dateext
        dateformat -%d%m%Y
        notifempty
        compress
        postrotate
                /etc/init.d/syslog-ng reload 2>/dev/null
        endscript
}

0****##########################################################
0****_sudo
echo 'password' | sudo -kS ls

0****##########################################################
0****_DNS_in_RHEL7
#Resolution Create a .conf file under /etc/NetworkManager/conf.d/resolv.conf and add the desired entries :
cat <<-EOF > /etc/NetworkManager/conf.d/resolv.conf
[main]
dns=default

[global-dns]
searches=int.se.nmc.ericsson.se

[global-dns-domain-*]
servers=153.88.33.66,153.88.33.67
EOF
#Restart the NetworkManager service.
systemctl restart  NetworkManager.service

0****##########################################################
0****_CIFS
//osesafs0001/Enable_Component_GlB_CL2 /Enable_Share cifs  credentials=/opt/.cifs_share_sec,iocharset=utf8,rw,uid=1000,gid=1000,file_mode=0777,dir_mode=0777,sec=ntlm 0 0

//osesafs0001/RPA_CentralizeDBbackup	/RPA-CDBbackup	cifs	credentials=/opt/.cifs_share,vers=1.0,iocharset=utf8,rw,file_mode=0777,dir_mode=0777,sec=ntlm 0 0 

0****##########################################################
0****_NOTEPAD++_LINE_Joining 3 lines
### Notes: Of course, don’t forget to check the Regular expression search mode !
### use the reges S/R, below :/

#### Replace "3" lines non-empty lines
SEARCH (?-s)^(.+)\R(.+)\R(.+)\R
REPLACE \1\2\3\r\n
\1,\2,\3,\4,\5,\6\r\n   <---REPLACE End of line with ","

#### Replace "6"  lines, first line non-empty and rest anything(empty or non-empty)
SEARCH (?-s)^(.+)\R(.*)\R(.*)\R(.*)\R(.*)\R(.*)\R
REPLACE \1\2\3\4\5\6\r\n

#### Replace multi-empty lines with single empty line
SEARCH (\r\n)(\r\n)+
REPLACE (\r\n)(\r\n)

1) The first part (?-s) means that any dot, in the regex, will stand for an unique standard character, exclusively
Then, the symbol ^ is an assertion, looking for a beginning of line
2) Next, the part (.+)\R, searches an entire, NON empty, line, with its End of Line characters, whatever they are and stored as group 1, due to the parentheses
3) Finally, the two next syntaxes (.+)\R look for the next two complete lines, stored as group 2 and group 3
4) In replacement, these three lines are re-written, one after another, on a same line, followed by the Windows End of Line characters. For Unix files, use the regex \1\2\3\n, instead

0****##########################################################
0****_SMTP_RELAY_INFO
Relay	IP	DC
smtp.int.se.nmc.ericsson.se	153.88.33.45  	Skondal
	153.88.33.46	
oselilx0001v.int.msdp.ericsson.se	172.29.36.24	Linkoping
osesalx0001v.int.msdp.ericsson.se	172.29.4.24		Akalla
ouspllx0001v.int.msdp.ericsson.se	172.29.68.24	Dallas Plano
ousaalx0001v.int.msdp.ericsson.se	172.29.100.24	New Jersey
oinnnolx0001v.int.msdp.ericsson.se	172.29.132.24	Noida
smtp.int.in.nmc.ericsson.se			150.236.127.50	Gurgaon
smtp.internal.ericsson.com			153.88.115.39	exchange-115-vip1.ss.sw.ericsson.se

0****##########################################################
0****_proxy_info
export http_proxy="http://www-proxy.ericsson.se:8080" 
export https_proxy="http://www-proxy.ericsson.se:8080"
export {http,https,ftp}_proxy="http://www-proxy.ericsson.se:8080"
unset export {http,https,ftp}_proxy

0****##########################################################
0****_disk_speed
dd if=/dev/input.file  of=/path/to/output.file  bs=block-size  count=number-of-blocks  oflag=dsync
 
## GNU dd syntax ##
dd if=/dev/zero of=/tmp/test1.img bs=200M count=1 oflag=dsync
 
## OR alternate syntax for GNU/dd ##
dd if=/dev/zero of=/opt_insite/testALT.img bs=200M count=1 conv=fdatasync

dd if=/opt_insite/test1.img of=/opt_insite/speedtest_out bs=1G count=100 conv=fdatasync
dd if=/opt_insite/test1.img of=/opt_insite/speedtest_out bs=1G count=1 conv=fdatasync

# Reading from the different filesystem & Writing on the same file system
dd if=/dev/zero of=/opt_insite/speedtest_out bs=1G count=1 conv=fdatasync

# Reading from the filesystem & Writing on back the same file system
dd if=/opt_insite/testALT.img of=/opt_insite/speedtest_out bs=1G count=1 conv=fdatasync

0****##########################################################
0****_DATE
date +"%d-%b-%Y_%H-%M-%S"

0****##########################################################
0****CPU_SOFT_Lock
sysctl kernel.softlockup_panic
sysctl kernel.watchdog_thresh
echo "kernel.softlockup_panic=0" >> /etc/sysctl.conf
echo "kernel.watchdog_thresh=60" >> /etc/sysctl.conf  
sysctl -p
sysctl kernel.softlockup_panic
sysctl kernel.watchdog_thresh

0****##########################################################
0****_kernel_
#/boot partition - recommended size at least 1 GiB
package-cleanup --oldkernels --count=1

0****##########################################################
0****yum
yum --disablerepo=* --enablerepo=rhel* repolist
yum --disablerepo=* --enablerepo=rhel* install telnet --assumeno

yum install --downloadonly --resolve --downloaddir=<directory> <package>

0****##########################################################
0****ip_commands
# Deleting Virtual / Secondary IP of a NIC
ip addr del 172.29.51.6/28 dev eth0

0****##########################################################
0****ip_route_RHEL6: ip route
To add a static route to a host address, in other words to a single IP address, issue a command as root:
ip route add 192.0.2.1 via 10.0.0.1 [dev ifname]

To add a static route to a network, in other words to an IP address representing a range of IP addresses, issue the following command as root:
ip route add 192.0.2.0/24 via 10.0.0.1 [dev ifname]

#cat /etc/sysconfig/network-scripts/route-eth0
default via 192.168.0.1 dev eth0
10.10.10.0/24 via 192.168.0.10 dev eth0
172.16.1.10/32 via 192.168.0.10 dev eth0

0****##########################################################
0****RHEL5 to RHEL6
Red Hat does not support in-place upgrades between major versions 5 and 6 of Red Hat Enterprise Linux. (A major version is denoted by a whole number version change. For example, Red Hat Enterprise Linux 5 and Red Hat Enterprise Linux 6 are both major versions of Red Hat Enterprise Linux).

So In-place upgrade from RHEL5 to RHGEL6 and RHEL5 to RHEL7 not possible.  However, if you intend to move from RHEL 5 to RHEL 7 . It is recommended to take back up of your data and restore data on a fresh installation of RHEL 6 or RHEL 7 system. Red Hat strongly recommends fresh installations while upgrading from RHEL5 to RHE6 or RHEL7.

0****##########################################################
0****crashkernel_size_chart
+---------------------------------------+
| RAM       | crashkernel | crashkernel |
| size      | memory      | offset      |
|-----------+-------------+-------------|
|  0 - 2G   | 128M        | 16M         | 
| 2G - 6G   | 256M        | 24M         | 
| 6G - 8G   | 512M        | 16M         |
| 8G - 24G  | 768M        | 32M         |
+---------------------------------------+

0****##########################################################
0****SWAP
lvcreate -L 8G -n swap rhel
mkswap /dev/rhel/swap
swapon -v /dev/rhel/swap

cp -p /etc/fstab /etc/fstab.4jan22.bkup
echo "/dev/mapper/rhel-swap swap swap defaults 0 0" >> /etc/fstab

 mount -av
 
0****##########################################################
0****Process_using_TOP_SWAP_
find /proc -maxdepth 2 -path "/proc/[0-9]*/status" -readable -exec awk -v FS=":" '{process[$1]=$2;sub(/^[ \t]+/,"",process[$1]);} END {if(process["VmSwap"] && process["VmSwap"] != "0 kB") printf "%10s %-30s %20s\n",process["Pid"],process["Name"],process["VmSwap"]}' '{}' \; | awk '{print $(NF-1),$0}' | sort -hr | head | cut -d " " -f2-

 
/ # Normal user is unable to login on the system with an error "fork: Resource temporarily unavailable"
 Increase the value of "nproc" parameter for user or all user's in /etc/security/limits.d/90-nproc.conf.
<user>     -          nproc     2048      <<<----[ Only for "<user>" user ]
*          	-          nproc     2048      <<<----[ For all user's ]
"# Determine the total number of process(es) on the system.
ps | wc -l

# Determine the process name with the highest number of instances.
ps | gawk '{count[$NF]++}END{for(j in count) print ""count[j]":",j}'|sort -rn|head -n20

0****##########################################################
0****Satellite_Server_Troubleshooting
0****##########################################################
1) Clear all paused and running tasks from Satellite .
foreman-rake foreman_tasks:cleanup TASK_SEARCH='label ~ *' STATES='paused,running' VERBOSE=true
2) Check  back in the postgres output and you should not see any paused or running tasks.
su - postgres -c "psql -d foreman -c 'select label,count(label),state,result from foreman_tasks_tasks where state <> '\''stopped'\'' group by label,state,result ORDER BY label;'"
3) foreman-maintain service restart
4) sleep 20 && hammer ping

# satellite-maintain service restart

0****##########################################################
0****Satellite_Client_Troubleshooting
0****##########################################################
subscription-manager refresh
yum clean all
yum repolist
subscription-manager release --show
subscription-manager identity

echo "yes" | cp -prf /etc/yum.repos.d /var/tmp
echo "yes" | rm -f /etc/yum.repos.d/*redhat*.repo
echo "yes" | rm -f /etc/yum.repos.d/*rhel*.repo
echo "yes" | rm -f /etc/yum.repos.d/*epel*.repo
echo "yes" | rm -rf /tmp/yum.repos.d; mkdir /tmp/yum.repos.d; mv /etc/yum.repos.d/*.repo /tmp/yum.repos.d/
echo "yes" | mv -f /etc/sysconfig/rhn/systemid /var/tmp
subscription-manager unsubscribe --all
subscription-manager remove --all
subscription-manager clean

#TROUBLESHOOTING STEPS - To Enable Satellite Registration & REPOS
subscription-manager register --org="Default_Organization" --activationkey="bmas_sdap_sca_rhel7_prod"
subscription-manager list --consum
subscription-manager attach --auto
subscription-manager refresh
subscription-manager config

0****##########################################################
0****RHVM_RHVH
0****##########################################################
# Enabling Global Maintenance Mode
#You must place the self-hosted engine environment in global maintenance mode before performing any setup or upgrade tasks on the Manager virtual machine.
#Log in to one of the self-hosted engine nodes and enable global maintenance mode:
hosted-engine --set-maintenance --mode=global

#Log in to one of the self-hosted engine nodes and disable global maintenance mode:
hosted-engine --set-maintenance --mode=none

#Confirm that the environment is in maintenance mode before proceeding:
hosted-engine --vm-status

#On the Red Hat Virtualization Manager machine, check if updated packages are available:
engine-upgrade-check

0****##############################################
0****_Troubleshooting_RHVM_Manager
0****##############################################
hosted-engine --vm-status
cat /var/log/ovirt-hosted-engine-ha/agent.log
/

systemctl start ovirt-ha-agent
systemctl status -l ovirt-ha-agent
hosted-engine --check-deployed
hosted-engine --vm-status

#When the self-hosted engine nodes are in global maintenance mode, the Manager virtual machine must be rebooted manually. If you try to reboot the Manager virtual machine by sending a reboot command from the command line, the Manager virtual machine will remain powered off. This is by design.
# Reboot the Manager virtual machine manually from one of the self-hosted engine nodes:
hosted-engine --vm-status
hosted-engine --vm-shutdown
hosted-engine --vm-start
hosted-engine --console

df -hTP
lsblk
cat /etc/fstab
gluster  volume status
gluster volume start Disvol-SSDN3a force
gluster volume start Disvol-SSDN2a
df -hTP
cat /var/log/glusterfs/$fuse-mount-point.log
mount -a
df -hTP
cat /etc/hosts
gluster  volume status
gluster volume stop Disvol-SSDN2a

0****##############################################
0****_WinSCP_to_Linux (Files Copy)
$ServerList = Get-Content "C:\zzzChandra\serverList1.txt"
$plinkPath = 'C:\Program Files (x86)\PuTTY\plink.exe'
$pscpPath = 'C:\Program Files (x86)\PuTTY\pscp.exe'

foreach ($i in $ServerList) {
    write-host $i
    Write-Output $i "==========================================================" | Out-File -FilePath C:\zzzChandra\output.txt -Append
    
    echo y | &($pscpPath) -l ZCHAMEDDOM -pw 'Tcs@nov21nmc' -P 22 'C:\zzzChandra\cs\falcon-sensor-6.25.0-12207.el6.x86_64.rpm' ${i}:/var/tmp/ | Out-File -FilePath C:\zzzChandra\output.txt -Append
	echo y | &($pscpPath) -l ZCHAMEDDOM -pw 'Tcs@nov21nmc' -P 22 'C:\zzzChandra\cs\falcon-sensor-6.25.0-12207.el7.x86_64.rpm' ${i}:/var/tmp/ | Out-File -FilePath C:\zzzChandra\output.txt -Append
    Write-Output "==========================================================" | Out-File -FilePath C:\zzzChandra\output.txt -Append
    Write-Output "`n" | Out-File -FilePath C:\zzzChandra\output.txt -Append
}


##### WORKING PSCP Lines Below####
# echo y | &($pscpPath) -l 'zchameddom' -pw 'Tcs@oct20dom' -P 22 "C:\zzzTemp\os_prechecks.txt" "${i}:/tmp/" | Out-File -FilePath C:\zzzTemp\output.txt -Append
# echo y | &($pscpPath) -l ZCHAMEDDOM -pw 'Tcs@oct20dom' -P 22 'C:\zzzTemp\agent_config.json' ${i}:/tmp/fireeye_agent | Out-File -FilePath C:\zzzTemp\output.txt -Append

0****##############################################
0****_