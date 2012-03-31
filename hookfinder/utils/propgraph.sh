#!/bin/bash

if [ $# -lt 3 ]
then
    echo "Usage: $0 tracefile depid output"
    exit 1
fi

BINDIR=`dirname $0`
VINETRUNK=$HOME/vine/trunk
TAINTTREE=$VINETRUNK/utils/tainttree

CMD1="$TAINTTREE -tainttrace $1 -targetid $2"

echo "+) Executing command: $CMD1"
$CMD1 > tmp-prop-graph.raw 2>/dev/null

CMD2="$BINDIR/formatdot.pl tmp-prop-graph.raw"
echo "+) Executing command: $CMD2 > $3" 
$CMD2 > $3

rm tmp-prop-graph.raw -f
