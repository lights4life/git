#!/bin/bash
printf "##################################################\n"
printf  "##### `date` \n"
UserSessions_TTY=$(w | grep -v 640|awk '{if (NR!=1) {print $2 }}' | tail -n +2)
for i in $UserSessions_TTY
do
pkill -9 -t $i
done
printf "##################################################\n"