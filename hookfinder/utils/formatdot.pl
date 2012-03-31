#!/usr/bin/perl 
use warnings;
use strict;

my $argc = @ARGV;
if ($argc < 1) {
    printf "Usage: %s inputfile\n", $0;
    exit 1;
}

my $input = $ARGV[0];

my %hashtbl; 
my %revhashtbl;

my %nodes;
my %edges;

open(INPUTDOT, $input);
while (<INPUTDOT>) {
    if (m/label-([0-9a-f]*)! (.*)!/) {
	$hashtbl{$1} = $2; 
	if (!$revhashtbl{$2}) {
	    $revhashtbl{$2} = $1; 
	}
    }
    
    if (m/digraph.*/) {
	print $_, "\n";
	last; 
    }
}

while (<INPUTDOT>) {
    if (m/(.*label=\")(label-)([0-9a-f]*)(\".*)/) {
	if ($hashtbl{$3}) {
	    my $info = $hashtbl{$3};
	    if (!$nodes{$info}) {
		print $1, $info, $4, "\n";
		$nodes{$info} = $3;
	    }
	} else {
	    print $_, "\n";
	}
    } else {
	if (m/(.*\")(.*)(\" -> \")(.*)(\".*)/) {
	    my $srcid = $2;
	    my $dstid = $4; 
	    
	    my $newsrcid = $srcid;

	    if ($hashtbl{$srcid} && $nodes{$hashtbl{$srcid}}) {
		$newsrcid = $nodes{$hashtbl{$srcid}};
	    }
	    
	    my $newdstid = $dstid;
	    if ($hashtbl{$dstid} && $nodes{$hashtbl{$dstid}}) {
		$newdstid = $nodes{$hashtbl{$dstid}}
	    }

	    my $edge = $newsrcid."->".$newdstid; 
	    if (!$edges{$edge}) {
		print $1, $newsrcid, $3, $newdstid, $5, "\n";
		$edges{$edge} = $edge; 
	    }
	} else {
	    print $_, "\n";
	}
    }
}
