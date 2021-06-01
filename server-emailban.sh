#!/bin/sh

script_name="${0##*/}"
if [ "$USER" != "root" ]; then
	echo "$script_name: run as root" >&2
	exit 1
fi

banlist=/etc/postfix/banlist
[ -f $banlist ] || echo "# $banlist" > $banlist

[ ${#@} -eq 0 ] && { echo "$script_name: Specify ban target" >&2; exit 1; }

bancode='550 "BLACKLISTED"'
# iterate arguments, add each to the ban list
for bantarget in $@; do
	# don't add if already on list
	! (grep -E "^$bantarget	*([5][0-9][0-9].*|REJECT.*)" $banlist) && \
		(echo "$bantarget		$bancode" >> $banlist)
done

postmap $banlist
