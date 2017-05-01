#!/bin/bash
file="../library/hosts"
NR_DOM=`xl list | wc -l`
COUNT=`expr $NR_DOM - 2`
for i in `seq 1 $COUNT`;
do
	echo "Working for dom$i"
	id=`xl list | awk -v VAR="dom${i}" 'BEGIN {pattern = VAR "[^0-9]"} $0 ~ pattern {print $2 }'`
	sed -i "s/10.0.0.${i}-[0-9]\+/10.0.0.${i}-${id}/g" $file
	echo "Replaced id with ID $id"
	`scp $file root@10.0.0.${i}:/root/`
done    
