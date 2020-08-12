#!/usr/bin/env bash

usage="$0 --subnet 192.168.0.0/24,192.168.1.1/32 [ --all --dns --nbt --verbose]"

if [[ -z $1 ]]
then
	error="TRUE"
fi

check_deps () {
	packages=(prips dig nmap nbtscan)
	for package in "${packages[@]}"
	do
		if ! command -v ${package} >/dev/null
		then
			failure='true'
			failed_packages+="${package}"
		fi
	done

	if  [ "$failure" == 'true' ]
	then
		echo "Please install ${failed_packages[*]}"
		exit 1
	fi
}

check_deps

parsedlist=()

subnetcheck () {
	subnetlist=$1
	if echo $1 | grep -q ','
	then
		for net in $(printf ${subnetlist} | tr "," "\n")
		do
			parsedlist+=( "${net}" )
		done
	else
		nolist="TRUE"
		parsedlist+=${subnetlist}
	fi

	if [[ ${nolist} == "TRUE" ]]
	then
		echo "${parsedlist}" | grep -q "/"
		if [ $? != 0 ]
		then
			echo "Please specify the IP ranges in CIDR format. Exiting."
			exit 1
		fi

		prips "${parsedlist}" > /dev/null
		if [ $? != 0 ]
		then
			export error="TRUE"
		fi
	else
		for net in "${parsedlist[@]}"
		do
			echo "${net}" | grep -q "/"
			if [ $? != 0 ]
			then
				echo "Please specify the IP ranges in CIDR format. Exiting."
				exit 1
			fi

			prips ${net} > /dev/null
			if [ $? != 0 ]
			then
				export error="TRUE"
			fi
		done
	fi
}

while [[ $# -gt 0 ]]; do
	value="$1"
	case ${value} in
		--subnet)
			shift
			subnetcheck $1
			;;
		-a|--all)
			export dns="TRUE"
			export nbt="TRUE"
			;;
		--dns)
			export dns="TRUE"
			;;
		--nbt)
			export nbt="TRUE"
			;;
		-v|--verbose)
			export verbose="TRUE"
			;;
		*)
			export error="TRUE"
			;;
	esac
	shift
done

if [[ "${error}" == "TRUE" ]]
then
	echo "${usage}"
	exit 0
fi

log () {
	message="$@"
	if [[ ${verbose} == "TRUE" ]]
	then
		printf "${message}\n"
	fi
}

dnsenum () {
	log "Scanning for DNS Servers..."
	dns_servers=$(nmap -sS ${parsedlist[@]} -p 53 --open | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	printf "Detected DNS Servers:\n${dns_servers}\n"
	for server in ${dns_servers}
	do
		log "Checking ${server} for any DNS names that resolve to ${server}."
		results=$(dig -x ${server} @${server} +short)
		if [[ -n ${results} ]]
		then
			echo "${server}: ${results}"
		fi

		log "Checking if any DNS names resolve to ${server} against all the DNS servers detected so far."
		for alt_server in ${dns_servers}
		do
			results=$(dig -x ${server} @${alt_server} +short)
			if [[ -n ${results} ]]
			then
				echo "${server}: ${results} (@${alt_server})"
			fi
		done
		
		log "Checking ${server} for DNS names that resolve in the target IP space."
		for net in ${parsedlist[@]}
		do
			ip_addresses=$(prips ${net})
			for ip in ${ip_addresses}
			do
				results="$(dig -x ${ip} @${server} +short)"
				if [[ -n ${results} ]]
				then
					echo "${ip}: ${results} (@${server})"
				fi
			done
		done
	done
}

nbtenum () {
	for net in ${parsedlist[@]}
	do
		log "Scanning ${net} for NBT"
		nbtscan -r ${net} 2>/dev/null
	done
}

main () {
	if [[ ${dns} == "TRUE" ]]
	then
		dnsenum
	fi

	if [[ ${nbt} == "TRUE" ]]
	then
		nbtenum
	fi
}

main
