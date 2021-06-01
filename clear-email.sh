#!/bin/sh

if [ "$USER" != "root" ]; then
	echo "${0##*/}: run as root" >&2
	exit 1
fi

## Systemd services
services="dovecot postfix opendkim opendmarc spamassassin"
## Arch
progs="$services pigeonhole"
## Debian
#progs="dovecot-core dovecot-imapd postfix opendkim opendmarc"

systemctl disable $services
systemctl stop $services

(id vmail 2>/dev/null)	&& userdel -r vmail
[ -f ./emailtodo.txt ]	&& rm ./emailtodo.txt
[ -d /var/vmail/ ]	&& rm -rf /var/vmail/
[ -d /etc/dovecot/ ]	&& rm -rf /etc/dovecot/
[ -d /etc/postfix/ ]	&& rm -rf /etc/postfix/
[ -d /var/spool/postfix/ ]	&& rm -rf /var/spool/postfix/
[ -f /etc/opendkim.conf ]	&& rm /etc/opendkim.conf
[ -f /etc/opendmarc.conf ]	&& rm /etc/opendmarc.conf
[ -d /etc/systemd/system/opendkim.service.d/ ] && rm -rf /etc/systemd/system/opendkim.service.d
[ -d /etc/systemd/system/opendmarc.service.d/ ] && rm -rf /etc/systemd/system/opendmarc.service.d
[ -d /etc/systemd/system/postfix.service.d/ ] && rm -rf /etc/systemd/system/postfix.service.d
[ -d /etc/dkimkeys/ ]	&& rm -rf /etc/dkimkeys/

## Arch
pacman -R $progs
pacman -S $progs

## Debian
#apt purge $progs
#apt install $progs
systemctl stop $services
