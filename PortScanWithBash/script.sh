#!/bin/bash
# Assign the network ID to a variable
network=$(echo $1 | cut -d / -f 1)
# Assign the destination folder to variable
folder=$HOME/nmap-scans/$network
# Check if the folder exists, if not, create it
[ -d $folder ] || mkdir -p $folder
# Assign the current date to a variable
today=$(date +%d-%m-%Y)
# Assign “yesterday” date to a variable
yesterday=$(date -d yesterday +%d-%m-%Y)
# Default TCP scan with Nmap - save the result in xml
nmap --max-retries 3 $1 -oX $folder/$today.xml
# Check if there is a report form yesterday and compare the results
if [ -f $folder/$yesterday.xml ]
then
ndiff $folder/$yesterday.xml $folder/$today.xml > $folder/$network.diff
cat $folder/$network.diff
fi