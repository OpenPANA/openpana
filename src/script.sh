#!/bin/bash

it=0
numbertest=510

it=$(($it + 1))

while [ $it -le $numbertest ]
do
	echo "Iteration number $it"
	echo "Starting PAA"
	./openpaa 2>>salida-server &
	#valgrind --trace-children=yes  --log-file=valgrind-server ./openpaa  &
	#PID1=$!
	#echo "Starting PRE"
	#valgrind --trace-children=yes --log-file=valgrind-relay ./openpre &
	#PID2=$!
	sleep 1

	echo "Starting PaC"
	./openpac 2>> salida-client &
	#valgrind --trace-children=yes --log-file=valgrind-client ./openpac &
	#PID3=$!
	#./openpac &

	echo "Waiting for (re-)authentication"
	sleep 5

	echo "Killing processes"
	#kill $PID1
	#kill $PID2
	#kill $PID3
	killall openpaa
	killall openpac
	#killall openpre

	echo " " >>salida-client
	echo " " >>salida-client
	echo " " >>salida-server
	echo " " >>salida-server
	sleep 1
	
	#cat valgrind-server >> server-memory-footprint
	#echo " " >>server-memory-footprint
	#echo " " >>server-memory-footprint
	#cat valgrind-relay >> relay-memory-footprint
	#echo " " >>relay-memory-footprint
	#echo " " >>relay-memory-footprint
	#cat valgrind-client >> client-memory-footprint
	#echo " " >>client-memory-footprint
	#echo " " >>client-memory-footprint
	
	it=$(($it + 1))
	
done


