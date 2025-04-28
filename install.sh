#!/bin/bash
Green='\033[0;32m'
white='\033[0;37m'
NC='\033[0m'
clear
printf '\033]2; INSTALLER\a'
echo -e "${Green}[*] Press \e[0;33many key\e[0;32m to install Pegasus-Xploit..."
read -n 1 
clear

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [[ "$DIR" != "/root/Pegasus-Xploit" ]]
then
	echo -e "\033[0;35m[~] I will install it for you..."
	sleep 4
	if [[ -d /root/Pegasus-Xploit ]]
	then 
		rm -r /root/Pegasus-Xploit
	fi
	mkdir /root/Pegasus-Xploit
	cp -r "$DIR"/* /root/Pegasus-Xploit
	chmod +x /root/Pegasus-Xploit/install.sh
	#gnome-terminal -- bash -c "sudo /root/bootmiester/install.sh; exec bash"
fi
echo -e "${Green}[+] Installing Pegasus-Xploit..."
sleep 1
echo -e "${Green}[+] Fixing permissions..."
sleep 2
chmod +x /root/Pegasus-Xploit/pegasus-xploit.sh
clear
echo -e "${Green}[+] Copying Tool to /bin/pegasus-xploit"
cd /root/Pegasus-Xploit
cp /root/Pegasus-Xploit/pegasus-xploit.sh /bin/pegasus-xploit
clear

while true
do  
	clear
	echo -e "${Green}[*] Are you \e[0;33mu\e[0;32mpdating or \e[0;33mi\e[0;32mnstalling the script?(\e[0;33mu\e[0;32m/\e[0;33mi\e[0;32m): "
	echo -e "${Green}[#] Only use 'i' for the first time."
	read UORI
	if [[ "$UORI" = "u" ]]
	then 
		clear 
		echo -e "This feature is currently under construction.."
		sleep 3
		exit
	elif [[ "$UORI" = "i" ]]
	then 
		clear
		BASHCHECK=$(cat ~/.bashrc | grep "/bin/pegasus-xploit")
		if [[ "$BASHCHECK" != "" ]]
		then 
			echo -e "I SAID USE i ONLY ONE TIME..........."
			sleep 3
			break
		fi
		echo -e "${Green}[#] Adding Pegasus-Xploit to PATH so you can access it from anywhere"
		sleep 1
		export PATH=/bin/pegasus-xploit:$PATH
		sleep 1
		echo "export PATH=/bin/pegasus-xploit:$PATH" >> ~/.bashrc
		sleep 1
		clear
		break
	fi
done
sleep 1
echo -e "${Green}[#] Installation is finished. Type 'sudo pegasus-xploit' to launch the script after we exit."
sleep 0.5
echo -en "${Green}[+] Starting Pegasus-Xploit"; sleep 0.5 ;echo -en "." ;sleep 0.5 ;echo -en "." ;sleep 0.5 ;echo -en "." ;sleep 0.5 ;echo -en "." ;
sudo pegasus-xploit


