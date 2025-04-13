#!/bin/bash
LINE="["

for i in 0.0 0.01 0.05 0.1    #$(seq 0 0.1 0.5)
do
    LINE+="["
    for s in 31 63 127 255 511 1023 1471
    do
        LINE+="$(./testN.sh 50 $@ -d 1 -i $i -s $s), \n"
    done
    LINE+="], \n"
done
LINE+="]"

echo $LINE