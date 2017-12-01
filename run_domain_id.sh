#!/bin/bash

echo "Run the code"
start=$1
end=$2

echo "We start with domain id $start and ends with domain id $end."
for (( i=$start;i<=$end;i++ ));
do
     echo $i
     python2 history_scan.py $i
     sleep 10
done

echo "Boom Finish it"