pam module that creates new users
=================================

intro
-----

pam_useradd creates accounts if they do not yet exist on the system.

Useful for e.g. shared computers where the users of the system are
not known before. A shared account which no or well known
password sucks as everyone messes with the settings and files of
others. So pam_useradd just dynamically creates new user accounts.

usage
-----

add the following line to e.g. /etc/pam.d/gdm (before other auth
lines):
> auth     optional       pam_useradd.so

... UTSL

security
--------

your default system policies should be set up in a way that new
users don't gain privileges that can be used to damage the system
obviously.

do not use the module with 'su'. It's not safe to be used in setuid
context.
