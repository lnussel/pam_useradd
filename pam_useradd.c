#if 0
set -- gcc -o ${0%%.*}.so -Wall -g -O2 -fPIC -shared $0
echo "$@"
exec "$@"
exit 1
#endif
/*
 * Copyright (C) 2011 Ludwig Nussel <ludwig.nussel@ff-egersdorf-wachendorf.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <crypt.h>
#include <security/pam_appl.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#ifdef HAVE_GCCVISIBILITY
#  define DLLEXPORT __attribute__ ((visibility("default")))
#  define DLLLOCAL __attribute__ ((visibility("hidden")))
#else
#  define DLLEXPORT
#  define DLLLOCAL
#endif

#ifndef PAM_EXTERN
#  define PAM_EXTERN
#endif

#define DIMOF(x) (sizeof(x)/sizeof(x[0]))

#ifndef _
#define _(x) (x)
#endif

char guestuser[128] = "guest";

static void freeresp(struct pam_response* resp, unsigned num)
{
	unsigned i;
	if(!resp)
		return;

	for(i = 0; i < num; ++i)
	{
		if(resp[i].resp)
			memset(resp[i].resp, 0, strlen(resp[i].resp));
		free(resp[i].resp);
	}
	free(resp);
}

static void freemsg(struct pam_message* msg, unsigned num)
{
	unsigned i;
	if(!msg)
		return;

	for(i = 0; i < num; ++i)
	{
		free((char*)msg[i].msg);
		msg[i].msg = NULL;
	}
}

static unsigned make_username(char username[], const char* user, size_t len)
{
	unsigned i;
	const char* p;
	for (i = 0, p = user; *p && i < len; ++p)
	{
		switch (*p)
		{
			case '0'...'9':
				if (!i) continue;
			case 'A'...'Z':
			case '_':
			case 'a'...'z':
				username[i++] = *p;
				break;
		}
	}
	if (i == len)
		username[len-1] = 0;
	return i;
}


// from pam_unix2
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')
static int getrandom_ascii(char* o)
{
	static char buf[4];
	static unsigned i = 0;
	if (i%sizeof(buf) == 0)
	{
		i = 0;
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd == -1)
			return -1;
		if (read(fd, buf, sizeof(buf)) != sizeof(buf))
			return -1;
		close(fd);
	}
	*o = bin_to_ascii(buf[i]&0x3f);
	++i;
	return 0;
}

static int gensalt(char salt[])
{
	if (getrandom_ascii(&salt[0]) == -1
	|| getrandom_ascii(&salt[1]) == -1)
		return -1;
	salt[2] = '\0';
	return 0;
}

static int add_user(const char*  user, const char* password, const char* comment)
{
	char* crypted;
	char salt[3];
	if (gensalt(salt) == -1)
		return -1;
	crypted = crypt(password, salt);

	syslog(LOG_WARNING, "add user %s, pass %s, comment %s", user, password, comment);

	pid_t pid = fork();
	if (pid == -1)
		return -1;
	else if (!pid)
	{
		execl("/usr/sbin/useradd", "useradd", "-m", "-p", crypted, "-c", comment, user, NULL);
		syslog(LOG_ERR, "exec failed: %m");
		exit(-1);
	}
	else
	{
		int status;
		pid_t ret = waitpid(pid, &status, 0);
		if (ret == -1)
			return -1;
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			return -1;
	}
	return 0;
}

static int doit(pam_handle_t * pamh)
{
	const struct pam_conv *conv;
	int ret;
	const void* ptr;
	const char* user;
	const char* password = NULL;

	ret = pam_get_item(pamh, PAM_CONV, &ptr);
	if(ret != PAM_SUCCESS)
	{
		syslog(LOG_WARNING, "%s %s %d no conversation function: %s",
				__FILE__, __FUNCTION__, getuid(), pam_strerror(pamh, ret));
		return ret;
	}
	conv = ptr;

	ret = pam_get_item(pamh, PAM_USER, &ptr);
	if(ret != PAM_SUCCESS)
		user = NULL;
	else
		user = ptr;

	/* no user was passed at pam_start. Prompt for user name and password */
	if (!user)
	{
		struct pam_message msg[32];
		const struct pam_message *pmsg[DIMOF(msg)];
		struct pam_response *resp = NULL;
		unsigned i;
		unsigned num_msg = 0;
		const char* prompt;

		for(i = 0; i < DIMOF(pmsg); ++i)
			pmsg[i] = &msg[i];

		ret = pam_get_item(pamh, PAM_USER_PROMPT, &ptr);
		if (ret == PAM_SUCCESS && ptr)
		{
			prompt = ptr;
		}
		else
		{
			prompt = _("Username: ");
		}

		msg[num_msg].msg_style = PAM_PROMPT_ECHO_ON;
		msg[num_msg].msg = strdup(prompt);
		++num_msg;
		msg[num_msg].msg_style = PAM_PROMPT_ECHO_OFF;
		msg[num_msg].msg = strdup(_("Password: "));
		++num_msg;

		syslog(LOG_WARNING, "starting conversation with %d prompts", num_msg);
		ret = conv->conv(num_msg, pmsg, &resp, conv->appdata_ptr);

		if(ret != PAM_SUCCESS)
		{
			syslog(LOG_WARNING, "conversation error: %s", pam_strerror(pamh, ret));
			// in error case caller is responsible
			// freeresp(resp, num_msg);
			return PAM_CONV_ERR;
		}

		if(!resp)
		{
			syslog(LOG_WARNING, "conversation error, response NULL");
			return PAM_CONV_ERR;
		}
		syslog(LOG_WARNING, "conversation done");

		ret = pam_set_item(pamh, PAM_USER, resp[0].resp);
		if (ret == PAM_SUCCESS)
			ret = pam_set_item(pamh, PAM_AUTHTOK, resp[1].resp);

		freeresp(resp, num_msg);
		freemsg(msg, num_msg);
		num_msg = 0;

		if(ret != PAM_SUCCESS)
			return PAM_IGNORE;
	}

	ret = pam_get_item(pamh, PAM_USER, &ptr);
	if(ret != PAM_SUCCESS)
		return PAM_IGNORE;
	else
		user = ptr;

	ret = pam_get_item(pamh, PAM_AUTHTOK, &ptr);
	if(ret == PAM_SUCCESS)
		password = ptr;

	/* continue with other pam modules if user exists and is not the guest user */
	if (user && strcmp(user, guestuser) && getpwnam(user))
	{
		syslog(LOG_WARNING, "ignoring %s", user);
		return PAM_IGNORE;
	}
	else
	{
		struct pam_message msg[32];
		const struct pam_message *pmsg[DIMOF(msg)];
		struct pam_response *resp = NULL;
		unsigned i;
		unsigned num_msg = 0;

		for(i = 0; i < DIMOF(pmsg); ++i)
			pmsg[i] = &msg[i];

		if (!password)
		{
			msg[num_msg].msg_style = PAM_PROMPT_ECHO_OFF;
			msg[num_msg].msg = strdup(_("Password: "));
			++num_msg;
		}
		msg[num_msg].msg_style = PAM_PROMPT_ECHO_OFF;
		msg[num_msg].msg = strdup(_("Confirm password: "));
		++num_msg;
		msg[num_msg].msg_style = PAM_PROMPT_ECHO_ON;
		msg[num_msg].msg = strdup(_("Full name: "));
		++num_msg;

		syslog(LOG_WARNING, "starting conversation2 with %d prompts", num_msg);
		ret = conv->conv(num_msg, pmsg, &resp, conv->appdata_ptr);
		if(ret != PAM_SUCCESS)
		{
			syslog(LOG_WARNING, "conversation error: %s", pam_strerror(pamh, ret));
			// in error case caller is responsible
			// freeresp(resp, num_msg);
			return PAM_CONV_ERR;
		}
		if(!resp)
		{
			syslog(LOG_WARNING, "conversation error, response NULL");
			return PAM_CONV_ERR;
		}
		syslog(LOG_WARNING, "conversation done");

		if (!resp[0].resp || (!password && !resp[1].resp))
		{
			syslog(LOG_ERR, "password(s) empty");
			ret = PAM_AUTH_ERR;
			goto out_free;
		}

		// do both passwords match?
		if ((password && strcmp(password, resp[0].resp))
		|| (!password && strcmp(resp[0].resp, resp[1].resp)))
		{
			syslog(LOG_ERR, "passwords don't match");
			ret = PAM_AUTH_ERR;
			goto out_free;
		}
		else
		{
			const char* fullname = resp[password?1:2].resp;
			char username[LOGIN_NAME_MAX];
			unsigned len = make_username(username, user, sizeof(username)-2);
			if (len < 2)
				len = make_username(username, fullname, sizeof(username)-2);
			if (len < 2)
			{
				syslog(LOG_WARNING, "user name too short");
				strcpy(username, guestuser);
			}
			
			{
				int cnt = 0;
				int pos = strlen(username);
				while(1)
				{
					if (cnt >= 100)
					{
						ret = PAM_AUTH_ERR;
						goto out_free;
					}
					if (!getpwnam(username) && strcmp(username, guestuser))
						break;
					syslog(LOG_WARNING, "user %s exists, retry", username);
					snprintf(username+pos, 3, "%02d", cnt);
				}
			}

			ret = add_user(username, resp[0].resp, fullname);
			if (ret != PAM_SUCCESS)
			{
				ret = PAM_AUTH_ERR;
				goto out_free;
			}
			ret = pam_set_item(pamh, PAM_USER, username);
			if (ret == PAM_SUCCESS && !password)
			{
				ret = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
				if (ret != PAM_SUCCESS)
					goto out_free;
			}
		}

out_free:
		freeresp(resp, num_msg);
		freemsg(msg, num_msg);
		num_msg = 0;

		if(ret != PAM_SUCCESS)
			return ret;
	}

	return PAM_IGNORE;
}

static void parse_args(const char* type, int argc, const char **argv)
{
	char file[PATH_MAX] = "/etc/security/pam_useradd.conf";
	int i;

	for(i=0; i < argc; ++i)
	{
		if(!strncmp(argv[i], "file=", 5))
		{
			strncat(file, argv[i]+5, sizeof(file)-1);
		}
	}
}

DLLEXPORT PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,int argc, const char **argv)
{
	char flagstr[1024] = "";

	if(flags&PAM_SILENT)
		strncat(flagstr, " PAM_SILENT", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_DISALLOW_NULL_AUTHTOK)
		strncat(flagstr, " PAM_DISALLOW_NULL_AUTHTOK", sizeof(flagstr)-strlen(flagstr)-1);

	syslog(LOG_WARNING, "%s %s uid:%d euid:%d%s", __FILE__, __FUNCTION__, getuid(), geteuid(), flagstr);

	parse_args("auth", argc, argv);

	return doit(pamh);
}

DLLEXPORT PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
