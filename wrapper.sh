#!/bin/sh

## the script to be executed by `ssh root@server.name [script]`
#	- only allows for certain executables to be run by root
#	- usefull for ban script (needs root permissions)

cmdpath=/root/bin
allowed="server-emailban.sh"

## remove leading pathname
cmd="${SSH_ORIGINAL_COMMAND##*/}"
cmd="${cmd%% *}"
args="${SSH_ORIGINAL_COMMAND#*$cmd}"

[ -z "$cmd" ] && { printf "specify command\nallowed -> $allowed\n" >&2 ; exit 1; }

for bin in $allowed; do
	[ "$cmd" = $bin ] && exec $cmdpath/$cmd $args
done

echo "cannot execute $cmd
allowed -> $allowed"

exit 0
