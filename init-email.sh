#!/bin/sh

systemd_unit_path=/etc/systemd/system
virtual_user=vmail
virtual_home=/var/$virtual_user
emailtodo=emailtodo.txt
dovecotdir=/etc/dovecot
dkimkeys=/etc/dkimkeys
selector=mail
opendmarcconf=/etc/opendmarc.conf
opendkimconf=/etc/opendkim.conf
virt_passwd=$dovecotdir/passwd
localhost=127.0.0.1
OS=$(awk '/^ID=/{ printf "%s", substr($1, 4) }' /etc/os-release)

POSTFIX=/sbin/postfix

# param: user
add_virt_user() {
	local user pass uid gid

	## create virtual_user
	if ! id $virtual_user 2>/dev/null; then
		useradd --system --shell /usr/sbin/nologin $virtual_user
		if [ ! -d $virtual_home ]; then
			mkdir $virtual_home
			chmod 700 $virtual_home
		fi
	fi

	user=${1:?missing username parameter (add_virt_user)}
	echo "Password for $user"
	pass=$(doveadm pw -s BLF-CRYPT)
	 uid=$(id -u $virtual_user)
	 gid=$(id -g $virtual_user)

	echo "$user:$pass:$uid:$gid::$virtual_home/$user/" >> $virt_passwd
	cd $virtual_home
	mkmaildir $user/Maildir
	mkmaildir $user/Maildir/Spam
	mkmaildir $user/Maildir/Sent

	mkdir $user/sieve
	cd $user/sieve

echo 'require ["fileinto", "envelope", "comparator-i;ascii-numeric", "relational", "spamtestplus"];

/*if address :is "to" "'$user'@'$(hostname)'" {
	fileinto "Important";
}*/
if spamtest :value "ge" :comparator "i;ascii-numeric" "10" {
	fileinto "Spam";
} else {
	keep;
}' > main.sieve
	ln -s ./main.sieve ./dovecot.sieve

	chown -R $virtual_user:$virtual_user $virtual_home
}

# param: maildir -> directory name for Maildir/ to be created
mkmaildir() {
	local maildir
	maildir=$1
	
	[ -z "$maildir" ] && { echo "missing mailbox parameter" >&2; exit 1; }
	[ "$maildir" = "cur" ] && { echo "bad mailbox name" >&2; exit 1; }
	[ "$maildir" = "new" ] && { echo "bad mailbox name" >&2; exit 1; }
	[ "$maildir" = "tmp" ] && { echo "bad mailbox name" >&2; exit 1; }
	mkdir -p $maildir/tmp/ \
		 $maildir/new/ \
		 $maildir/cur/
}

## sanity tests
if [ "$USER" != "root" ]; then
	echo "${0##*/}: run as root" >&2
	exit 1
fi
[ -d $dovecotdir ] || cp -r /usr/share/doc/dovecot/example-config/ $dovecotdir
[ -d $dovecotdir/private/ ] || mkdir $dovecotdir/private/
if [ ! -d $dkimkeys ]; then
	mkdir $dkimkeys
	chmod 700 $dkimkeys
	chown -R opendkim:opendkim $dkimkeys
fi
postfix_queue_dir=/var/spool/postfix
[ -d $postfix_queue_dir/etc/ ] || mkdir $postfix_queue_dir/etc/
[ -f $postfix_queue_dir/etc/services ] || cp /etc/services $postfix_queue_dir/etc/services
[ -f $postfix_queue_dir/etc/resolv.conf ] || cp /etc/resolv.conf $postfix_queue_dir/etc/resolv.conf

# basic config
[ -d $systemd_unit_path/postfix.service.d/ ] || mkdir $systemd_unit_path/postfix.service.d/
echo '[Unit]
Description=Postfix Mail Transport Agent
Conflicts=sendmail.service exim4.service
After=network.target
ConditionPathExists=/etc/postfix/main.cf

[Service]
ExecStart=
ExecStart=/usr/sbin/postfix start
ExecStop=
ExecStop=/usr/sbin/postfix stop
ExecReload=
ExecReload=/usr/sbin/postfix reload
RemainAfterExit=no
PIDFile=/var/spool/postfix/pid/master.pid
Restart=always
Type=forking
PrivateDevices=true
PrivateTmp=true
ProtectSystem=true

[Install]
WantedBy=multi-user.target' > $systemd_unit_path/postfix.service.d/override.conf
echo '' > $systemd_unit_path/'postfix@.service'

[ -f /etc/postfix/main.cf ] || cp /etc/postfix/main.cf.proto /etc/postfix/main.cf
postconf -e \
	'html_directory=/usr/share/doc/postfix/html' \
	'manpage_directory=/usr/share/man' \
	'readme_directory=/usr/share/doc/postfix' \
	'queue_directory=/var/spool/postfix' \
	'sample_directory=/etc/postfix' \
	'mailq_path=/usr/bin/mailq' \
	'newaliases_path=/usr/bin/newaliases' \
	'sendmail_path=/sbin/sendmail' \
	'setgid_group=postdrop' \
	'inet_protocols=all' \
	'home_mailbox=Maildir/' \
	'mynetworks_style=host' \
	'mynetworks=127.0.0.0/8' \
	'myorigin=$mydomain' \
	'relay_domains=' \
	'relayhost=' \
	'mydestination='

banlist=/etc/postfix/banlist
# simple spam filtering
postconf -e \
	'smtpd_sender_restrictions=check_sender_access hash:'$banlist',reject_unknown_sender_domain' \
	'smtpd_helo_restrictions=reject_unknown_helo_hostname' \
	'smtpd_helo_required=yes' \
	'smtpd_data_restrictions=reject_multi_recipient_bounce' \
	'smtpd_recipient_restrictions=reject_non_fqdn_recipient, reject_unauth_destination' \
	'strict_rfc821_envelopes=yes' \
	'smtpd_reject_unlisted_sender=yes' \
	'smtpd_client_restrictions=sleep 1, reject_unauth_pipelining, check_client_access hash:'$banlist
echo "# $banlist" > $banlist
postmap $banlist
newaliases

## postscreen
postconf -e \
	'postscreen_dnsbl_sites=zen.spamhaus.org*2,bl.spamcop.net*1' \
	'postscreen_dnsbl_threshold=2' \
	'postscreen_dnsbl_action=enforce' \
	'postscreen_greet_action=enforce'

#+master.cf stuff

## opendkim
dkimverify=/etc/postfix/dkim-verify.txt
dkimprivkey=/etc/dkimkeys/dkim.key
dkimport=8892

openssl genpkey -algorithm RSA -out ${dkimprivkey}

dnsdomainname > ${dkimverify}
hostname >> ${dkimverify}

echo '## '$opendkimconf'
Syslog			yes
UMask			007

# Sign for example.com with key in /etc/dkimkeys/dkim.key using
# selector '2007' (e.g. 2007._domainkey.example.com)
Domain			'${dkimverify}'
KeyFile			'${dkimprivkey}'
Selector		'${selector}'

Socket			inet:'${dkimport}'@localhost
#PidFile			/run/opendkim/opendkim.pid (uncomment on debian)


#OversignHeaders		From

#TrustAnchorFile       /usr/share/dns/root.key
UserID                opendkim' > $opendkimconf

smtpd_milters=${smtpd_milters},inet:$localhost:$dkimport
non_smtpd_milters=${non_smtpd_milters},inet:$localhost:$dkimport

# put in dns records
printf 'dkim dns txt record
'$selector'._domainkey
k=rsa\; p=' >> $emailtodo
openssl rsa -pubout -in ${dkimprivkey} 2>/dev/null | sed '/PUBLIC/d' | tr -d '\n' >> $emailtodo
printf "\n\n" >> $emailtodo

[ ! -d $systemd_unit_path/opendkim.service.d ] && mkdir $systemd_unit_path/opendkim.service.d
echo '[Unit]
Description=OpenDKIM DomainKeys Identified Mail (DKIM) Milter
Documentation=man:opendkim(8) man:opendkim.conf(5) man:opendkim-genkey(8) man:opendkim-genzone(8) man:opendkim-testadsp(8) man:opendkim-testkey http://www.opendkim.org/docs.html
After=network.target nss-lookup.target 

[Service]
Type=forking
PIDFile=
#PIDFile=/run/opendkim/opendkim.pid (uncomment on debian)
UMask=0007
ExecStart=
ExecStart=/usr/sbin/opendkim -x '$opendkimconf'
Restart=on-failure
#ExecReload=/bin/kill -USR1 $MAINPID

[Install]
WantedBy=multi-user.target' > $systemd_unit_path/opendkim.service.d/override.conf

## opendmarc
dmarcport=$(( $dkimport + 1 ))
# conf file
echo '## '$opendmarcconf'
#PidFile /run/opendmarc/opendmarc.pid (uncomment on debian)

#PublicSuffixList /usr/share/publicsuffix

Socket inet:'${dmarcport}'@localhost

Syslog true
UMask 0002
UserID opendmarc' > $opendmarcconf

[ ! -d $systemd_unit_path/opendmarc.service.d ] && mkdir $systemd_unit_path/opendmarc.service.d
# .service file
echo '[Unit]
Description=OpenDMARC Milter
Documentation=man:opendmarc(8) man:opendmarc.conf(5)
After=network.target nss-lookup.target 

[Service]
Type=forking
PIDFile=
#PIDFile=/run/opendmarc/opendmarc.pid (can uncomment on debian)
User=opendmarc
ExecStart=
ExecStart=/usr/sbin/opendmarc -c '$opendmarcconf'
Restart=on-failure
#ExecReload=/bin/kill -USR1 $MAINPID

[Install]
WantedBy=multi-user.target' > $systemd_unit_path/opendmarc.service.d/override.conf

smtpd_milters=${smtpd_milters},inet:$localhost:$dmarcport

## spamassassin
# TODO os-dependent
#sa-update

# dns records
echo ' -dmarc dns txt record-
_dmarc.'$(hostname)'
v=DMARC1\; adkim=r\; p=quarantine' >> $emailtodo

## -TLS-
postfixcert=/etc/postfix/tls/tlscert.pem
postfixkey=/etc/postfix/tls/tlskey.pem
dovecotcert=/etc/dovecot/private/dovecot.pem
dovecotkey=/etc/dovecot/private/dovecot.key
realcert=/etc/letsencrypt/live/$(hostname)/fullchain.pem
realkey=/etc/letsencrypt/live/$(hostname)/privkey.pem

## sym-links
[ -d /etc/postfix/tls/ ] || mkdir /etc/postfix/tls/
[ -h $postfixcert ] || ln -s $realcert $postfixcert
[ -h $postfixkey ]  || ln -s $realkey  $postfixkey
[ -h $dovecotcert ] && rm $dovecotcert
[ -h $dovecotkey ]  && rm $dovecotkey
ln -s $realcert $dovecotcert
ln -s $realkey  $dovecotkey

postconf -e \
	"tls_random_source = dev:/dev/urandom" \
	"smtpd_tls_cert_file = $postfixcert" \
	"smtpd_tls_key_file = $postfixkey" \
	"smtpd_tls_security_level = may" \
	"smtp_tls_security_level = may"

echo '## 10-ssl.conf
# SSL settings
ssl = yes

ssl_cert = <'$dovecotcert'
ssl_key = <'$dovecotkey'

ssl_client_ca_dir = /etc/ssl/certs'> $dovecotdir/conf.d/10-ssl.conf

# -GENERAL DOVECOT-
echo "## 10-auth.conf
# Auth
disable_plaintext_auth = yes
auth_mechanisms = plain

# Password and user databases

!include auth-passwdfile.conf.ext" > $dovecotdir/conf.d/10-auth.conf

echo '## 10-mail.conf
# Mailbox locations and namespaces
mail_location = maildir:'$virtual_home/'%u/Maildir:LAYOUT=fs
namespace inbox {
  inbox = yes
  separator = '/'
}

mail_privileged_group = mail

protocol !indexer-worker {
}' > $dovecotdir/conf.d/10-mail.conf

echo "## 10-master.conf
service imap-login {
  inet_listener imap {
    port = 143
    address = localhost
  }
  inet_listener imaps {
    #port = 993 TODO OBSCURE
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 0
  }
  inet_listener pop3s {
    port = 0
  }
}

service submission-login {
  inet_listener submission {
  }
}

service lmtp {
  unix_listener lmtp {
  }
}

service imap {
}
service pop3 {
}
service submission {
}

service auth {
  unix_listener auth-userdb {
    #mode = 0666
    #user = 
    #group = 
  }

  # Postfix smtp-auth
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

service auth-worker {
}

service dict {
  unix_listener dict {
  }
}" > $dovecotdir/conf.d/10-master.conf

echo "## dovecot.conf
# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol

listen = *, ::

dict {
}

!include conf.d/*.conf
!include_try local.conf" > $dovecotdir/dovecot.conf

# -DOVECOT (VIRTUAL USERS)-

virtual_aliases=/etc/postfix/virtual
postconf -e \
	'virtual_mailbox_domains = $myhostname, $mydomain, localhost, localhost.$mydomain' \
	'virtual_transport = dovecot' \
	'virtual_alias_maps = hash:'$virtual_aliases

## adding user
read -p "Who is the main user? > " main_user
add_virt_user $main_user
echo '# /etc/postfix/virtual

# important
postmaster              '$main_user'@bagcal.xyz
root                    '$main_user'@bagcal.xyz' > $virtual_aliases
postmap $virtual_aliases

echo '## 15-lda.conf
# LDA specific settings (also used by LMTP)

sendmail_path = /usr/sbin/sendmail
lda_mailbox_autocreate = no

protocol lda {
	mail_plugins = $mail_plugins sieve
}

service auth {
	unix_listener auth-userdb {
		mode = 0600
		user = '$virtual_user'
		group = '$virtual_user'
	}
}' > $dovecotdir/conf.d/15-lda.conf

echo '# auth-passwdfile.conf.ext
# Authentication for passwd-file users. Included from 10-auth.conf.

passdb {
  driver = passwd-file
  args = scheme=CRYPT username_format=%u '$virt_passwd'
}

userdb {
  driver = passwd-file
  args = username_format=%u '$virt_passwd'
}' > $dovecotdir/conf.d/auth-passwdfile.conf.ext

echo '# 10-metrics.conf
## fix stats-writer error
service stats {
  client_limit = 10000
  unix_listener stats-writer {
    user = '$virtual_user'
    #mode = 0666
  }
}' > $dovecotdir/conf.d/10-metrics.conf

## TODO default script
echo '# 90-sieve.conf
plugin {
  sieve = file:~/sieve/;active=~/sieve/dovecot.sieve
  
  sieve_extensions = +spamtest +spamtestplus
  sieve_spamtest_status_type = "strlen"
  sieve_spamtest_status_header = X-Spam-Level
  #sieve_spamtest_max_value = 5.0
  sieve_spamtest_max_header = \
  X-Spam-Status: [[:alnum:]]+, score=-?[[:digit:]]+\.[[:digit:]] required=([[:digit:]]+\.[[:digit:]])
}' > $dovecotdir/conf.d/90-sieve.conf

## master.cf
#	+set postscreen
#	+submission port
#	+dovecot-lda
echo '# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master" or
# on-line: http://www.postfix.org/master.5.html).
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
#smtp      inet  n       -       y       -       -       smtpd
smtp      inet  n       -       y       -       1       postscreen
smtpd     pass  -       -       y       -       -       smtpd
dnsblog   unix  -       -       y       -       0       dnsblog
tlsproxy  unix  -       -       y       -       0       tlsproxy
'"#8039"' inet  n       -       y       -       -       smtpd
submission inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_sasl_security_options=noanonymous,noplaintext
  -o smtpd_sasl_tls_security_options=noanonymous
#  -o smtpd_client_restrictions=$mua_client_restrictions
#  -o smtpd_helo_restrictions=$mua_helo_restrictions
#  -o smtpd_sender_restrictions=$mua_sender_restrictions

#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=postfix/$service_name
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
#
# ====================================================================
# Interfaces to non-Postfix software. Be sure to examine the manual
# pages of the non-Postfix software to find out what options it wants.
#
# Many of the following services use the Postfix pipe(8) delivery
# agent.  See the pipe(8) man page for information about ${recipient}
# and other message envelope options.
# ====================================================================
#
# maildrop. See the Postfix MAILDROP_README file for details.
# Also specify in main.cf: maildrop_destination_recipient_limit=1
#
#maildrop  unix  -       n       n       -       -       pipe
#  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#
# ====================================================================
#
# See the Postfix UUCP_README file for configuration details.
#
#uucp      unix  -       n       n       -       -       pipe
#  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
#
## spamassassin + dovecot
dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user='$virtual_user':'$virtual_user' argv=/usr/bin/vendor_perl/spamc 
  -u spamd -e /usr/lib/dovecot/dovecot-lda -f ${sender} -d ${user}' > /etc/postfix/master.cf


# set milters
postconf -e \
	"smtpd_milters=${smtpd_milters#,}" \
	"non_smtpd_milters=${non_smtpd_milters#,}"

systemd_services="postfix.service opendkim.service opendmarc.service dovecot.service spamassassin.service"
systemctl daemon-reload
systemctl enable $systemd_services
systemctl restart $systemd_services

exit 0
