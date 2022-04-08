##### Please find below commands for vas and user access.

# Check ACCESS & SUDO
echo "*************************Check ACCESS:"
ls -ltr /etc/opt/quest/vas/lastjoin
/opt/quest/bin/vastool user checkaccess KTLAVELUUQ
pam_tally2 --user=ergparaadm
pam_tally2 --user=ergparaadm --reset
echo "*************************Check SUDO:"
sudo -l -U ergparaadm
grep -v "^#" /etc/sudoers | head -10
echo "*************************Check VAS & SUDO RPM:"
rpm -qa | grep -i vas
rpm -qa | grep -i sudo
echo "*************************Check LAST Join DATE:"
ls -ltr /etc/opt/quest/vas/lastjoin


# ACCESS ISSUE
/opt/quest/bin/vastool user checkaccess USER_ID
pam_tally2 --user=USER_ID
#pam_tally2 --user=USER_ID --reset

# SUDO ISSUE
sudo -l -U USER_ID
rpm -qa | grep -i vas
grep -v "^#" /etc/sudoers | head -10
#sudo issue, if sudo does not work in vasd
#Defaults always_query_group_plugin

/opt/quest/bin/vastool list -a users
/opt/quest/bin/vastool list -a groups

Will list all the policies applicable 					--> /opt/quest/bin/vgptool listgpc
Check a user’s RO access              					--> /opt/quest/bin/vastool user checkaccess USER_ID
Check a user’s sudo access           				    --> sudo -l -U USER_NAME
Flush cached client daemon information		--> /opt/quest/bin/vgptool flush 		      
Sync/Apply Group Policy settings      				--> /opt/quest/bin/vgptool apply 		      
Last join DNS join                    							--> more /etc/opt/quest/vas/lastjoin
# Domain Info
echo "Tcs@nov21nmc" | /opt/quest/bin/vastool -s -u zchameddom info servers

for syncing the time with DNS server manually real time  --> /opt/quest/bin/vastool timesync

# Domain joining NMC
/opt/quest/bin/vastool -u zchameddom join -f nmc.ericsson.se
echo "Tcs@nov21nmc" | /opt/quest/bin/vastool -s -u zchameddom join -f nmc.ericsson.se

# Domain Info
echo "Tcs@nov21nmc" | /opt/quest/bin/vastool -s -u zchameddom info servers

/opt/quest/bin/vastool -u zchameddom join -f nmc.ericsson.se
/opt/quest/bin/vastool -u zchameddom join -f -n minnolx015v nmc.ericsson.se
/opt/quest/bin/vastool -u zchameddom join -f -s SEKI nmc.ericsson.se
/opt/quest/bin/vastool -u zchameddom join -f -n <server-name> OU=Unix,OU=Ericsson,OU=Servers,OU=SEKI,DC=nmc,DC=ericsson,DC=se -s SEKI nmc.ericsson.se

# Domain joining SDT
/opt/quest/bin/vastool -u ztceroqfas join -f ericsson.se
echo "Tcs@nov21sdt" | /opt/quest/bin/vastool -s -u ztceroqfas join -f ericsson.se


# to apply any changes immediatly to VAS Tool
/opt/quest/bin/vgptool apply  

Check a user’s RO access --> /opt/quest/bin/vastool list users|grep bash
# /opt/quest/bin/vastool list
--------------------------------------------------------------------
Usage: vastool list [-alcsptgnfo] {command}

Commands:
  users
  users-allowed
  users-denied
  user {username}
  groups
  group {groupname}
  netgroup {netgroup name}
  netgroups
  negcache

-a List all groups/users (including non-Unix enabled ones)
-l Bypass vasd cache and use ldap lookups
-c Read straight from cache without updating from Active Directory
-s Print the objectSid in the group output
-p Print primaryGroupID in the user output
-t Print primaryGroupToken in the group output
-g Print objectGUIDs associated with this object in the form :
-n Print userAccountControl value in user output
-f Force vasd to update its cache
-o Process override information
--------------------------------------------------------------------

# QAS daemon is operating in a disconnected state
1. Check to ensure the domain controllers are reachable.
# /opt/quest/bin/vastool info cldap  ericsson.se
2. If domain controller are available, try restarting vasd to see if another server is picked up. Then re-run the vastool status command to check if it  reports healthy.
3.   Note the information reported by this command: 
/opt/quest/bin/vastool info servers  
Rejoin the server to AD :  
/opt/quest/bin/vastool -u ADUSER  join -f  YOURDOMAIN.com
/opt/quest/bin/vastool -u ztceroqfas join -s Semea00 -f ericsson.se

### Please run an ldap ping against the DC's returned by "vastool info servers" command:
[root@pose02lx0092v ~]# /opt/quest/bin/vastool info servers
Servers type = DC, domain = ericsson.se, site = Semea00:
SESBIWEGAD00005.ericsson.se
sesbiwegad0001.ericsson.se
sessiwegad00007.ericsson.se
sesbiwegad00007.ericsson.se

### Please run an ldap ping against the DC's returned by "vastool info servers" command:
#/opt/quest/bin/vastool info cldap ericsson.se
A healthy response time:
Query Response Time:     0.0028 seconds
Anything over a second is pretty slow.
Check your /etc/resolv.conf and ensure it is setup properly. 
Check your DNS servers are healthy. 

NOTE: Contact your networking team to resolve or check DNS Configuration.

#####################################################################
https://redhatlinux.guru/2016/04/05/65/              ---troubelshhoting vas related issues

vasd cheet sheet commands
Important Files
Files					            Details
/etc/opt/quest/vas/host.keytab    	Encrypted host key 
/etc/opt/quest/vas/group-override  	Maps accounts to groups 
/etc/opt/quest/vas/users.allow		Lists groups that are granted access to the server 
/etc/opt/quest/vas/xjoin.keytab 	File used to join server to domain 
/etc/opt/quest/vas/vas.conf 		Primary VAS configuration file 
/etc/opt/quest/vas/user-override 	Allows you to override specific user settings 

Basic Commands
Command 					             Details
/opt/quest/bin/vastool status			 status View status about the operating environment 
/opt/quest/bin/vgptool flush 		     Flush cached client daemon information 
/opt/quest/bin/vgptool apply 		     Apply Group Policy settings 
/opt/quest/bin/vastool user checkaccess  [account] Check rather user has access to he system and which group grants that access 
/opt/quest/bin/vastool ktutil list	 List entries in the keytab file 

Linux VAS Service Command Reference
Command 					Details
service vasd start 			Start vas service 
service vasd stop 			Stop vas service 
service vasd restart 		Restart vas service

##### Allow only few users & restrict other users
Before restart or reload ssh services , you have to inform user. 
/etc/pam.d/ssh - Append following line:
auth required pam_listfile.so item=user sense=allow file=/etc/ssh/ssh.allow onerr=fail

/etc/ssh/ssh.allow - Append username per line (also add our team member adm account)

/sbin/service sshd reload


##### Request will be raised from service request managaemnt-->request entry-->MSDP-->Admin access to MSDP servers
While creating a new adm accounts. Only create in the below mentioned path.
1 - open active roles server console
2 - add user into NMC -> INGU -> Admins
Policy: SEKI Unix login Mate  -- for sudo access need to add this group.

Advanced search 
View SR
Addtn details
Aprrover should be 
Puneet komal sreevastsav


Object type --> computer

=> Edit
   ----policies
   ----------Unix settings
   -----------------quest
   --------------------client conf
   ------------------------sudo
   --------------------Access conf
   -------------------------User allow
=> Create adm access
     admin
     ->INGU
     -->admins
     ---->properties
===================================================================
1.dsa.msc--> check whether he have adm account or not ..serch 

2.activerole server console-->
NMC
	INGU
		Admin

New - user -next -password -uncheck - next-finish

3.dsa.msc-->search adm - properties - account - unix enable

4.check policy in server
  /opt/quest/bin/vgptool list
5.gpcgpmc.msc
   check for the policy  
===========================

##### Group Policy
Policy(gpmc.msc)
      |           
Adding a server
      |
Add group to user.allow
or sudo

RO -->  only add in user.allow

create Group (dsa.msc with same groupname)
       |
Unix enable

##### CUPS
cups
  |
search group name
  |
add members with specific time

##### Dont give access on VIP
We dont manage VIP servers

##### Solaris VAS Service Command Reference
Command 					Details
svcadm enable svc:/quest/vas/vasd:default 	Start vas service 
svcadm disable svc:/quest/vas/vasd:default 	Stop vas service 
svcadm restart svc:/quest/vas/vasd:default 	Restart vas service