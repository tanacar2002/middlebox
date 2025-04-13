#!/bin/bash
max=$1
sum=0.0
LINE="["

for i in `seq 1 $max`
do
    LINE+="$(${@:2} | grep -o " [0-9]*\.[0-9]* kbps" | cut -d" " -f 2)"
    LINE+=", "
    # sleep 0.1
done
LINE+="]"

echo $LINE