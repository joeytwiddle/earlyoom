#!/bin/sh

[ -z "$COLUMNS" ] && COLUMNS=`tput cols`

(

	echo "PID adj s_adj score cmdline"

	grep -v '^0$' /proc/*/oom_score |
	cut -d / -f 3 |
	while read pid
	do
		oom_adj=`cat /proc/$pid/oom_adj`
		oom_score_adj=`cat /proc/$pid/oom_score_adj`
		oom_score=`cat /proc/$pid/oom_score`
		cmdline=`cat /proc/$pid/cmdline | tr '\0' ' '`
		echo "$pid $oom_adj $oom_score_adj $oom_score $cmdline"
	done |
	sort -n -k 4 -k 1

) |
columnise-clever -ignore "[^ ]* *[^ ]* *[^ ]* *[^ ]* *[^ ]*" |
cut -c 1-$COLUMNS
