#!/usr/bin/env bash
outdir="$(pwd)/out"
mkdir -p ${outdir}
usage="$0 --subnet 192.168.0.0/24,192.168.1.1/32 [ --all --dns --nbt --http --http-crawl ] --verbose"

if [[ -z $1 ]]
then
	error="TRUE"
fi

check_deps () {
	packages=(prips dig masscan nmap nbtscan httprobe meg)
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
			export http="TRUE"
			export http="TRUE"
			export http_crawl="TRUE"
			;;
		--dns)
			export dns="TRUE"
			;;
		--nbt)
			export nbt="TRUE"
			;;
		--http)
			export http="TRUE"
			;;
		--http-crawl)
			export http="TRUE"
			export http_crawl="TRUE"
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
	mkdir -p ${outdir}/dns
	log "Scanning for DNS Servers..."
	dns_servers=$(nmap -sS ${parsedlist[@]} -p 53 --open -n | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	printf "Detected DNS Servers:\n"
	printf "${dns_servers}\n" | tee -a ${outdir}/dns/servers.txt
	echo "---------------------------------------"
	for server in ${dns_servers}
	do
		log "Checking ${server} for any DNS names that resolve to ${server}."
		results=$(dig -x ${server} @${server} +short)
		if [[ -n ${results} ]]
		then
			printf "${server}: ${results} (@${server})\n" | tee -a ${outdir}/dns/resolve.txt
		fi

		log "Checking if any DNS names resolve to ${server} against all the DNS servers detected so far."
		for alt_server in ${dns_servers}
		do
			results=$(dig -x ${server} @${alt_server} +short)
			if [[ -n ${results} ]]
			then
				echo "${server}: ${results} (@${alt_server})" | tee -a ${outdir}/dns/resolve.txt
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
					echo "${ip}: ${results} (@${server})" | tee -a ${outdir}/dns/resolve.txt
				fi
			done
		done
	done
}

nbtenum () {
	mkdir -p ${outdir}/nbt
	for net in ${parsedlist[@]}
	do
		log "Scanning ${net} for NBT"
		nbtscan -r ${net} 2>/dev/null | tee -a ${outdir}/nbt/nbt.txt
	done
}

httpenum () {
	mkdir -p ${outdir}/http
	log "Scanning for HTTP(S) servers"
	http_servers=$(nmap -sS ${parsedlist[@]} -p80,443,8080 --open -n | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	printf "Detected HTTP Servers:\n${http_servers}\n"
	echo "---------------------------------------"

	uris=()
	for ip in ${http_servers}
	do
		log "Probing ${ip} for HTTP/HTTPS"
		result="$(echo ${ip} | httprobe -p 8080 -t 2000 | tee -a ${outdir}/http/hosts.txt)" &&\
			uri_detected="TRUE"
		if [[ -n ${result} ]]
		then
			echo ${result}
			for line in ${result}
			do
				uris+=${line}
			done
		fi
	done

	if [[ -e ${outdir}/http/hosts.txt ]]
	then
		cat ${outdir}/http/hosts.txt | sort -u > ${outdir}/http/hosts.txt.sorted && mv ${outdir}/http/hosts.txt.sorted ${outdir}/http/hosts.txt
	fi

	if [[ ${http_crawl} == "TRUE" ]]
	then
		mkdir -p ${outdir}/http/crawl 
		log "Crawling web hosts for paths"
		meg ${paths_file} ${outdir}/http/hosts.txt ${outdir}/http/crawl --concurrency 5 --delay 1000  --verbose -t 2000  --savestatus 200
	fi
}

main () {
	if [[ ${http_crawl} == "TRUE" ]]
	then
		if [[ -e paths ]]
		then
			export paths_file=./paths
		elif [[ -e /etc/paths ]]
		then
			export paths_file=/etc/paths
		elif [[ -e /tmp/paths ]]
		then
			export paths_file=/tmp/paths
		else 
			echo "No URI paths file detected. Please add paths file to ./paths, /etc/paths or /tmp/paths."
			exit 0
		fi
	fi
	if [[ ${dns} == "TRUE" ]]
	then
		dnsenum
		printf "\n"
	fi

	if [[ ${nbt} == "TRUE" ]]
	then
		nbtenum
		printf "\n"
	fi
	if [[ ${http} == "TRUE" ]]
	then
		httpenum
		printf "\n"
	fi
}

main
