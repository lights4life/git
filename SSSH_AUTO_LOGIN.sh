### 1. Passing clear text password <<<<< NOT Recommeded for automation
sshpass -p 't@uyM59bQ' ssh -o StrictHostKeyChecking=no user@server

### 2. Passing clear text password from a file <<<<< NOT Recommeded for automation
sshpass -f busrvac040_pass_file ssh -o StrictHostKeyChecking=no busrvac040@POSE01LX0031V

Create a file as follows:
*******************
$ echo 'myPassword' > myfile
$ chmod 0400 myfile
$ sshpass -f myfile ssh vivek@server42.cyberciti.biz

### 3. Passing clear text password from a environment variable  <<<<< NOT Recommeded for automation
sshpass uses SSHPASS environment variable to store user passwords. 
export SSHPASS=ry3AvbWO0oupYX9HCMzp0Axx
sshpass -e ssh  -o StrictHostKeyChecking=no user@server

### 4. use sshpass with gpg encrypted file <<<<< Recommeded for automation
vi busrvac040_pass_file #type your password here into the file
gpg -c busrvac040_pass_file #creates file with .gpg extension, busrvac040_pass_file.gpg
rm busrvac040_pass_file
gpg -d -q busrvac040_pass_file.gpg > busrvac040_gpg_passfile; sshpass -f busrvac040_gpg_passfile ssh -o StrictHostKeyChecking=no user@server
sshpass -d 1 busrvac040_pass_file.gpg ssh -o StrictHostKeyChecking=no busrvac040@POSE01LX0031V


Linux:
busrvac040    SD@39fDSeKLic93e#$0b7e52eb4a#7XD#4E16
root C0mm0n_L@b

############## SSH Credentials Auto Script ####################
userNAME=`cat userNameFile`
cat /dev/null > serverLIST.out
for serverNAME in `cat serverLIST`; do
printf "***********************************************\n" >> serverLIST.out
sshpass -f passFile ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no $userNAME@$serverNAME 2>>serverLIST.out; sshSTATUS=$?
printf "$serverNAME, username: $userNAME, sshSTATUS: $sshSTATUS \n" >> serverLIST.out
printf "***********************************************\n\n\n" >> serverLIST.out
done
###########################################################


###########################################################
SSHPASS ReTURN VALUES:
*******************************************************
      As  with  any  other  program, sshpass returns 0 on success. In case of
       failure, the following return codes are used:

       1      Invalid command line argument

       2      Conflicting arguments given

       3      General runtime error

       4      Unrecognized response from ssh (parse error)

       5      Invalid/incorrect password

       6      Host public key is unknown. sshpass exits without confirming the
              new key.

       In addition, ssh might be complaining about a man in the middle attack.
       This complaint does not go to the tty. In other words, even  with  ssh-
       pass,  the error message from ssh is printed to standard error. 
	   In such a case ssh’s return code is reported back. This is typically an unimag-
       inative (and non-informative) "255" for all error cases.
###########################################################