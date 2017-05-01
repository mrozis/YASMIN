#!/bin/bash
xenstore-write /local/domain/0/data/vchan 1
NR_DOM=`xl list | wc -l`
COUNT=`expr $NR_DOM - 2`
for i in `seq 1 $COUNT`;
do
	id=`xl list | awk -v VAR="dom${i}" 'BEGIN {pattern = VAR "[^0-9]"} $0 ~ pattern {print $2 }'`
	`xenstore-chmod -r /local/domain/0/data/vchan b${id}`
done    
