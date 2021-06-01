#!/bin/sh

systemctl status postfix dovecot opendkim opendmarc spamassassin

ss -tpln | grep -E '(587|889[23]|993|25|783)'
