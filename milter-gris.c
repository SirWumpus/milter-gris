/*
 * milter-gris.c
 *
 *	"Summoned, I take the place that has been prepared
 *	for me. I am Grey. I stand between the candle and
 *	the star. We are Grey. We stand between the
 *	darkness and the light."
 *	 - Delenn, All Alone in the Night, Babylon 5
 *
 * Copyright 2004, 2006 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-gris',
 *		`S=unix:/var/lib/milter-gris/socket, T=S:30s;R:3m'
 *	)dnl
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef CACHE_FILE
#define CACHE_FILE			"/var/cache/" MILTER_NAME ".db"
#endif

#ifndef DEFAULT_GREY_LIST_KEY
#define DEFAULT_GREY_LIST_KEY		(GREY_LIST_IP|GREY_LIST_MAIL|GREY_LIST_RCPT)
#endif

/*
 * Cache the entry for one week.
 */
#ifndef DEFAULT_TTL
#define DEFAULT_TTL			(7 * 86400)
#endif

/*
 * Initial temporary block period is 10 minutes.
 */
#ifndef DEFAULT_BLOCK_TIME
#define DEFAULT_BLOCK_TIME		(2 * 300)
#endif

/*
 * Allow no more than N attempts to deliver mail during the
 * block period. More than that and you're looking at a mail
 * server thats processing a message queue too frequently,
 * which from a mail administrator point of view is looks more
 * like a spam cannon.
 *
 * Set to 0 to disable.
 */
#ifndef DEFAULT_REJECT_COUNT
#define DEFAULT_REJECT_COUNT		0
#endif

#define X_SCANNED_BY			"X-Scanned-By"
#define X_MILTER_PASS			"X-" MILTER_NAME "-Pass"
#define X_MILTER_REPORT			"X-" MILTER_NAME "-Report"

#undef ENABLE_BLACKLIST

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <com/snert/lib/version.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Cache.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/setBitWord.h>
#include <com/snert/lib/sys/Time.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 63
# error "LibSnert/1.63 or better is required"
#endif

#ifdef MILTER_BUILD_STRING
# define MILTER_STRING	MILTER_NAME"/"MILTER_VERSION"."MILTER_BUILD_STRING
#else
# define MILTER_STRING	MILTER_NAME"/"MILTER_VERSION
#endif

#ifndef IS_IP_LAN
#define IS_IP_LAN		(IS_IP_PRIVATE_A|IS_IP_PRIVATE_B|IS_IP_PRIVATE_C|IS_IP_LINK_LOCAL|IS_IP_SITE_LOCAL)
#endif

#ifndef IS_IP_LOCAL
#define IS_IP_LOCAL		(IS_IP_THIS_HOST|IS_IP_LOCALHOST|IS_IP_LOOPBACK)
#endif

#ifndef IS_IP_LOCAL_OR_LAN
#define IS_IP_LOCAL_OR_LAN	(IS_IP_LAN|IS_IP_LOCAL)
#endif

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define GREY_LIST_IP		1
#define GREY_LIST_HELO		2
#define GREY_LIST_MAIL		4
#define GREY_LIST_RCPT		8

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

extern smfInfo milter;

struct bitword keyBitWords[] = {
	{ ~0,			"all" },
	{ GREY_LIST_IP, 	"ip" },
	{ GREY_LIST_HELO, 	"helo" },
	{ GREY_LIST_MAIL, 	"mail" },
	{ GREY_LIST_RCPT, 	"rcpt" },
	{ 0, 			NULL }
};

typedef struct {
	sfsistat status;
	time_t touched;
	unsigned long count;
} CacheEntry;

#define CACHE_SCANF_FORMAT	"%d %lx %lu"
#define CACHE_SCANF_DOT(v)	&(v).status, (long *) &(v).touched, &(v).count
#define CACHE_SCANF_ARROW(v)	&(v)->status, (long *) &(v)->touched, &(v)->count

#define CACHE_PRINTF_FORMAT	"%d %lx %lu"
#define CACHE_PRINTF_DOT(v)	(v).status, (long) (v).touched, (v).count
#define CACHE_PRINTF_ARROW(v)	(v)->status, (long) (v)->touched, (v)->count

static volatile Cache cache;
static volatile long connectionCount;
static CacheEntry cacheUndefinedEntry = { X_SMFIS_UNKNOWN, 0, 0 };

typedef struct {
	smfWork work;
	int status;				/* per message */
	int is_lan;				/* per connection */
	int is_ip_in_ptr;			/* per connection */
	int fromPostmaster;			/* per message */
	char helo[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

static const char usage_grey_list_key[] =
  "A comma separated list of what composes the grey-list key:\n"
"# ip, helo, mail, rcpt\n"
"#"
;

static const char usage_block_time_static[] =
  "Grey list block time in seconds if the SMTP client appears to\n"
"# be connecting from a static IP address. Specify -1 to disable.\n"
"#"
;


static Option optIntro			= { "",				NULL,		"\n# " MILTER_NAME "/" MILTER_VERSION "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optAcceptNullSender	= { "accept-null-sender",	"+",		"Do not grey list the null address used for DSN and MDN." };
static Option optBlockTime		= { "block-time",		"600",		"Grey list block time in seconds." };
static Option optBlockTimeStatic	= { "block-time-static",	"-1",		usage_block_time_static };
static Option optCacheAcceptTTL		= { "cache-accept-ttl",		"604800",	"Cache time-to-live in seconds for positive responses." };
static Option optCacheFile		= { "cache-file",		CACHE_FILE,	"Cache file path for bdb or flatfile types." };
static Option optCacheGcFrequency	= { "cache-gc-frequency", 	"250",		"Cache garbadge collection frequency." };
static Option optCacheTempFailTTL	= { "cache-temp-fail-ttl",	"90000",	"Cache time-to-live in seconds for temporary rejections." };
static Option optCacheType		= { "cache-type",		"bdb",		"Cache type from one of: bdb, flatfile, hash" };
static Option optGreyListKey		= { "grey-list-key",		"ip,mail,rcpt",	usage_grey_list_key };

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders		= { "add-headers",		"-",		"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
	&optAcceptNullSender,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&optBlockTime,
	&optBlockTimeStatic,
	&optCacheAcceptTTL,
	&optCacheFile,
	&optCacheGcFrequency,
	&optCacheTempFailTTL,
	&optCacheType,
	&optGreyListKey,
	NULL
};

/***********************************************************************
 *** Cache Support
 ***********************************************************************/

int
cacheGet(workspace data, char *name, CacheEntry *entry)
{
	int rc;
	Data value;
	struct data key;

	rc = -1;
	*entry = cacheUndefinedEntry;
	DataInitWithBytes(&key, name, strlen(name)+1);

	if (pthread_mutex_lock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex lock in cacheGet() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	value = cache->get(cache, &key);

	if (pthread_mutex_unlock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex unlock in cacheGet() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	if (value != NULL) {
		if (value->length(value) == sizeof (CacheEntry)) {
			*entry = *(CacheEntry *)(value->base(value));
			rc = 0;
		}
		value->destroy(value);
	}

	smfLog(SMF_LOG_CACHE, TAG_FORMAT "cache get key={%s} value={" CACHE_PRINTF_FORMAT "} rc=%d", TAG_ARGS, name, CACHE_PRINTF_ARROW(entry), rc);

	return rc;
}

/* This is an imperfect solution for call-back systems since it only works
 * for MX's own domain and not those it hosts. We don't need this if we temp.
 * fail at the DATA command instead.
 */

int
cacheGetDomain(workspace data, char *tag, char *domain, CacheEntry *entry)
{
	char *key;
	int resolved;
	size_t tlength, klength, length;

	if (tag == NULL)
		tag = "";

	smfLog(SMF_LOG_CACHE, TAG_FORMAT "cache get domain {%s%s}", TAG_ARGS, tag, domain);

	tlength = strlen(tag);

	/* Allocate enough room to hold the largest possible string. */
	klength = tlength + SMTP_DOMAIN_LENGTH + 1;
	if ((key = calloc(1, klength)) == NULL)
		goto error0;

	(void) snprintf(key, klength, "%s", tag);

	/* If the domain didn't resolve, then its an ip as domain name form
	 * so we only want to do one lookup on the whole and avoid the parent
	 * domain lookups.
	 */
	resolved = domain[0] != '[';

	/* Assume that the domain starts with a leading dot (.) */
	domain--;

	do {
		(void) strncpy(key + tlength, domain+1, klength - tlength);
		TextLower(key, -1);
		length = strlen(key);

		/* Remove trailing (root) dot just before the '\0' from domain name. */
		if (1 < length && key[length - 1] == '.')
			key[--length] = '\0';

		if (cacheGet(data, key, entry) == 0) {
			free(key);
			return 0;
		}
	} while (resolved && (domain = strchr(domain+1, '.')) != NULL && domain[1] != '\0');

	free(key);
error0:
	return -1;
}

static int
cacheUpdate(workspace data, char *name, CacheEntry *entry, sfsistat status)
{
	int rc;
	Data current;
	struct data key, value;

	entry->count = 0;
	DataInitWithBytes(&key, name, strlen(name)+1);

	if (pthread_mutex_lock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex lock in cacheUpdate() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	if ((current = cache->get(cache, &key)) != NULL) {
		*entry = *(CacheEntry *)(current->base(current));
		current->destroy(current);
	}

	entry->count++;
	entry->status = status;
#ifdef HMM
	entry->touched = time(NULL);
#endif
	DataInitWithBytes(&value, (unsigned char *) entry, sizeof (*entry));
	rc = cache->put(cache, &key, &value);

	if (pthread_mutex_unlock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex unlock in cacheUpdate() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	smfLog(SMF_LOG_CACHE, TAG_FORMAT "cache update key={%s} value={" CACHE_PRINTF_FORMAT "} rc=%d", TAG_ARGS, name, CACHE_PRINTF_ARROW(entry), rc);

	return rc;
}

int
cacheExpireEntries(void *key, void *value, void *data)
{
	time_t *now = data;
	CacheEntry *entry = (CacheEntry *) ((Data) value)->base(value);

	switch (entry->status) {
	case SMFIS_TEMPFAIL:
		if (*now < entry->touched + optCacheTempFailTTL.value)
			return 1;
		break;
	case SMFIS_CONTINUE:
		if (*now < entry->touched + optCacheAcceptTTL.value)
			return 1;
		break;
	}

	smfLog(SMF_LOG_CACHE, "cache remove key={%s} value={" CACHE_PRINTF_FORMAT "} age=%ld", ((Data) key)->base(key), CACHE_PRINTF_ARROW(entry), *now - entry->touched);

	return -1;
}

int
cacheGarbageCollect(workspace data)
{
	time_t now = time(NULL);

	if (pthread_mutex_lock(&smfMutex))
		syslog(LOG_ERR, "mutex lock in cacheGarbageCollect() failed: %s (%d) ", strerror(errno), errno);

	connectionCount++;

	smfLog(SMF_LOG_CACHE, "%ld connections", connectionCount);

	if (optCacheGcFrequency.value <= connectionCount) {
		smfLog(SMF_LOG_CACHE, "garbage collecting cache");

		cache->walk(cache, cacheExpireEntries, &now);
		connectionCount = 0;

		smfLog(SMF_LOG_CACHE, "syncing cache");

		if (cache->sync(cache))
			syslog(LOG_ERR, "cache sync error: %s (%d)", strerror(errno), errno);
	}

	if (pthread_mutex_unlock(&smfMutex))
		syslog(LOG_ERR, "mutex unlock in cacheGarbageCollect() failed: %s (%d) ", strerror(errno), errno);

	return 0;
}

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	long length;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	length = TextCopy(data->client_name, sizeof (data->client_name), client_name);
	TextLower(data->client_name, length);
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE)
		goto error1;

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	data->is_lan = isReservedIP(data->client_addr, IS_IP_LOCAL_OR_LAN);

	/* When block-time-static is disabled, then use block-time
	 * which should always be defined.
	 */
	if (optBlockTimeStatic.value < 0)
		optBlockTimeStatic.value = optBlockTime.value;

	if (raw_client_addr->sa_family == AF_INET
	&& isIPv4InClientName(data->client_name, (unsigned char *) &((struct sockaddr_in *) raw_client_addr)->sin_addr)) {
		data->is_ip_in_ptr = 1;
	}

	return SMFIS_CONTINUE;
error1:
	free(data);
error0:
	/* In the case of an internal error, we can reject the message or
	 * accept it. Accepting it would by-pass the milter, but allow the
	 * message to be received and maybe filtered by something else.
	 */
	return SMFIS_ACCEPT;
}

static sfsistat
filterHelo(SMFICTX * ctx, char *helohost)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHelo");

	/* Reset this again. A HELO/EHLO is treated like a RSET command,
	 * which means we arrive here after the connection but also after
	 * MAIL or RCPT, in which case $i (data->work.qid) is invalid.
	 */
	data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHelo(%lx, '%s')", TAG_ARGS, (long) ctx, helohost);

	if (helohost != NULL)
		TextCopy(data->helo, sizeof(data->helo), helohost);

	return SMFIS_CONTINUE;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;
	const char *auth_authen;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	data->status = SMFIS_CONTINUE;
	data->work.skipMessage = data->work.skipConnection;
	data->fromPostmaster = 0;

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	access = smfAccessMail(&data->work, MILTER_NAME "-from:", args[0], SMDB_ACCESS_UNKNOWN);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender authorisation <%s> denied", auth_authen);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);
	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	case SMDB_ACCESS_OK:
		syslog(LOG_INFO, TAG_FORMAT "sender %s authenticated, accept", TAG_ARGS, args[0]);
		return SMFIS_ACCEPT;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	time_t now;
	workspace data;
	long i, length;
	CacheEntry entry;

	now = time(NULL);

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	switch (smfAccessRcpt(&data->work, MILTER_NAME "-to:", args[0])) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	case SMDB_ACCESS_OK:
		return SMFIS_CONTINUE;
	}

	if (optAcceptNullSender.value) {
		if (*data->work.mail->address.string == '\0')
			return SMFIS_CONTINUE;

		/* Allow call-backs using <postmaster@...>; see
		 * milter-sender's MxCallBackAsPostmaster option.
		 * Postfix has a similar option I'm told. See also
		 * filterData() below.
		 */
		if (TextInsensitiveCompare(data->work.mail->localLeft.string, "postmaster") == 0) {
			data->fromPostmaster = 1;
			return SMFIS_CONTINUE;
		}
	}

	if (optBlockTimeStatic.value == 0 && !data->is_ip_in_ptr) {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "client %s [%s] looks static, skipping connection", TAG_ARGS, data->client_name, data->client_addr);

		/* Do not auto white list on this condition. */
		return SMFIS_CONTINUE;
	}

	if (data->work.skipMessage) {
		if (*data->work.mail->address.string != '\0') {
			/* The connection or sender may have been white listed,
			 * so we want to auto white list possible replies from
			 * the recipient back to the sender. If the recipient
			 * was white listed this generates a redundant cache
			 * entry.
			 */
			snprintf(data->line, sizeof (data->line), "auto,%s,%s", data->work.mail->address.string, data->work.rcpt->address.string);
			TextLower(data->line, -1);

			if (cacheUpdate(data, data->line, &entry, SMFIS_CONTINUE))
				syslog(LOG_WARNING, TAG_FORMAT "failed to auto white list reply for {%s}", TAG_ARGS, data->line);

if (milter.handlers.xxfi_version < 4) {
/* This is an imperfect solution for call-back systems since it only works
 * for MX's own domain and not those it hosts. We don't need this if we temp.
 * fail at the DATA command instead.
 */
			snprintf(data->line, sizeof (data->line), "auto,%s,%s", data->work.mail->address.string, data->work.rcpt->domain.string);
			TextLower(data->line, -1);

			if (cacheUpdate(data, data->line, &entry, SMFIS_CONTINUE))
				syslog(LOG_WARNING, TAG_FORMAT "failed to auto white list DSN for {%s}", TAG_ARGS, data->line);

}
		}

		return SMFIS_CONTINUE;
	}

	/* Check to see if the RCPT auto white listed replies from MAIL. */
	snprintf(data->line, sizeof (data->line), "auto,%s,%s", data->work.rcpt->address.string, data->work.mail->address.string);
	TextLower(data->line, -1);
	if (cacheGet(data, data->line, &entry) == 0) {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "reply from <%s> to <%s> expected, skipping", TAG_ARGS, data->work.mail->address.string, data->work.rcpt->address.string);
		return SMFIS_CONTINUE;
	}

if (milter.handlers.xxfi_version < 4) {

/* This is an imperfect solution for call-back systems since it only works
 * for MX's own domain and not those it hosts. We don't need this if we temp.
 * fail at the DATA command instead.
 */
	/* Check to see if the RCPT auto white listed DSN from domain. We
	 * base this check on the HELO argument, which is assumed to be a
	 * FQDN of the connecting client MX, anything else is grey listed
	 * as usual. This allows for call-back validation without grey
	 * listing delays.
	 *
	 * This test is not based on the client IP, because we would have
	 * had to auto white list each MX, which in turn might have been
	 * multi-homed; consider aol.com with 4 MXes, each which is multi-
	 * homed 4 or 5 times.
	 */
	if (*data->work.mail->address.string == '\0' && *data->helo != '\0') {
		snprintf(data->line, sizeof (data->line), "auto,%s,", data->work.rcpt->address.string);
		TextLower(data->line, -1);
		if (cacheGetDomain(data, data->line, data->helo, &entry) == 0) {
			smfLog(SMF_LOG_INFO, TAG_FORMAT "DSN to <%s> expected, skipping", TAG_ARGS, data->work.rcpt->address.string);
			return SMFIS_CONTINUE;
		}
	}

}

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "now=%lx", TAG_ARGS, now);

	/* THE TEST
	 *
	 * Construct the lookup key tuple...
	 */
	length = 0;
	for (i = GREY_LIST_IP; i <= GREY_LIST_RCPT; i <<= 1) {
		switch (optGreyListKey.value & i) {
		case GREY_LIST_IP:
			length += snprintf(data->line + length, sizeof (data->line) - length, "%s,", data->client_addr);
			break;
		case GREY_LIST_HELO:
			length += snprintf(data->line + length, sizeof (data->line) - length, "%s,", data->helo);
			break;
		case GREY_LIST_MAIL:
			length += snprintf(data->line + length, sizeof (data->line) - length, "%s,", data->work.mail->address.string);
			break;
		case GREY_LIST_RCPT:
			length += snprintf(data->line + length, sizeof (data->line) - length, "%s,", data->work.rcpt->address.string);
			break;
		}
	}

	/* Remove trailing comma. */
	data->line[length-1] = '\0';

	/* Flatten the case, since Sendmail tends to be case-insensitive.
	 * Local-parts are case sensitive, but Sendmail doesn't care.
	 */
	TextLower(data->line, -1);

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "key={%s}", TAG_ARGS, data->line);

	/* ...Then check if we have already seen this tuple before...
	 */
	if (cacheGet(data, data->line, &entry)) {
		/* We have never seen this tuple before, prepare an entry
		 * in the TEMPFAIL state.
		 */
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "no grey listing for {%s}", TAG_ARGS, data->line);

		entry.status = SMFIS_TEMPFAIL;
		entry.touched = now;
		entry.count = 0;
	}

	/* ...If so, is the tuple still in the TEMPFAIL state? ...
	 */
	if (entry.status == SMFIS_TEMPFAIL) {
		/* Is the tuple still being temporarily blocked? See the
		 * -b option.
		 */
		if (now < entry.touched + (data->is_ip_in_ptr ? optBlockTime.value : optBlockTimeStatic.value)) {
                        if (cacheUpdate(data, data->line, &entry, SMFIS_TEMPFAIL))
                                syslog(LOG_WARNING, TAG_FORMAT "failed to grey list {%s} in cache", TAG_ARGS, data->line);

			smfLog(
				SMF_LOG_INFO,
				TAG_FORMAT "denied grey listing {%s} for %ld seconds",
				TAG_ARGS, data->line,
				entry.touched + (data->is_ip_in_ptr ? optBlockTime.value : optBlockTimeStatic.value) - now
			);
#ifdef OFF
			if (4 <= milter.handlers.xxfi_version) {
				/* Defer this rejection until the DATA command.
				 * This allows call-back schemes like milter-sender
				 * and grey listing to work better together, since
				 * a call-back should never send a message.
				 */
				data->status = SMFIS_TEMPFAIL;

				return SMFIS_CONTINUE;
			}
#endif
			return smfReply(&data->work, 450, "4.7.1", "try again later");
		}

		/* Once we get this far, we know the number of delivery
		 * attempts was reasonable and that the server appears
		 * to queue mail, so we can upgrade the state to CONTINUE.
		 */
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "upgrading grey listing for {%s}", TAG_ARGS, data->line);

		entry.status = SMFIS_CONTINUE;
	}

	/* Touch a new or an existing entry so as to maintain active tuples. */
	entry.touched = now;
	if (cacheUpdate(data, data->line, &entry, entry.status))
		syslog(LOG_WARNING, TAG_FORMAT "failed to touch grey listing for {%s}", TAG_ARGS, data->line);

	smfLog(SMF_LOG_INFO, TAG_FORMAT "accepted grey listing {%s}", TAG_ARGS, data->line);

	/* ...Otherwise the tuple must be in the CONTINUE state and the message
	 * is allowed to pass. Eventually the entry will expire from the cache
	 * and grey-listing process will be repeated once more. See -c option.
	 */
	return SMFIS_CONTINUE;
}

#if SMFI_VERSION > 3
static sfsistat
filterData(SMFICTX * ctx)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterData");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterData(%lx)", TAG_ARGS, (long) ctx);

	/* We now allow MAIL FROM:<postmaster@...> as an alternative
	 * to MAIL FROM:<> only for call-backs by other sites. However,
	 * we block any attempt to send an actual message to anyone to
	 * avoid spammers abusing MAIL FROM:<postmaster@...> as they do
	 * MAIL FROM:<>.
	 *
	 * The RFC 2821 states we must accept RCPT TO:<postmaster> and
	 * RCPT TO:<postmaster@one.of.ours>. It also allows some limited
	 * filtering to <postmaster> and does not require us to accept
	 * MAIL FROM:<postmaster@some.place>.
	 */
	if (data->fromPostmaster && !data->work.skipMessage  && !data->is_lan && strcmp(smfOptInterfaceIp.string, data->client_addr) != 0)
		return smfReply(&data->work, 550, "5.7.1", "Message from <%s> not permitted.", data->work.mail->address.string);

	if (data->status == SMFIS_TEMPFAIL)
		return smfReply(&data->work, 450, "4.7.1", "try again later");

	return SMFIS_CONTINUE;
}
#endif

#ifdef DROPPED_ADD_HEADERS
static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	int length;
	workspace data;
	const char *if_name, *if_addr;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if ((if_name = smfi_getsymval(ctx, "{if_name}")) == NULL)
		if_name = smfUndefined;
	if ((if_addr = smfi_getsymval(ctx, "{if_addr}")) == NULL)
		if_addr = "0.0.0.0";

	length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ",  if_name, if_addr);
	length += TimeStampAdd(data->line + length, SMTP_TEXT_LINE_LENGTH - length);
	(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);

	return SMFIS_CONTINUE;
}
#endif

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		cacheGarbageCollect(data);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}

/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_VERSION,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		0,			/* flags */
		filterOpen,		/* connection info filter */
		filterHelo,		/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		NULL,			/* header filter */
		NULL,			/* end of header */
		NULL,			/* body block filter */
#ifdef DROPPED_ADD_HEADERS
		filterEndMessage,	/* end of message */
#else
		NULL,			/* end of message */
#endif
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, filterData		/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

static void
atExitCleanUp()
{
	smdbClose(smdbAccess);

	if (cache != NULL) {
		if (pthread_mutex_lock(&smfMutex))
			syslog(LOG_ERR, TAG_FORMAT "mutex lock in atExitCleanUp() failed: %s (%d) ", 0, smfNoQueue, strerror(errno), errno);

		cache->sync(cache);
		cache->destroy(cache);

		if (pthread_mutex_unlock(&smfMutex))
			syslog(LOG_ERR, TAG_FORMAT "mutex unlock in atExitCleanUp() failed: %s (%d) ", 0, smfNoQueue, strerror(errno), errno);
	}

	smfAtExitCleanUp();
}

int
main(int argc, char **argv)
{
	int argi;

	/* Defaults */
	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (optBlockTime.value < 0) {
		syslog(LOG_ERR, "block-time cannot be a negative number");
		return 2;
	}

	if (optCacheTempFailTTL.value <= optBlockTime.value) {
		syslog(LOG_ERR, "block-time must be less than cache-ttl");
		return 2;
	}

	if (optBlockTime.value < optBlockTimeStatic.value) {
		syslog(LOG_ERR, "block-time-static must be less than or equal to block-time");
		return 2;
	}

	optGreyListKey.value = setBitWord(keyBitWords, optGreyListKey.string);
	if (optGreyListKey.value == 0 || 16 <= optGreyListKey.value) {
		syslog(LOG_ERR, "invalid grey-list-key value");
		return 2;
	}

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	CacheSetDebug(smfLogDetail & SMF_LOG_CACHE);

	if ((cache = CacheCreate(optCacheType.string, optCacheFile.string)) == NULL) {
		syslog(LOG_ERR, "failed to create cache\n");
		return 1;
	}

	(void) smfSetFileOwner(&milter, optCacheFile.string);

	return smfMainStart(&milter);
}
