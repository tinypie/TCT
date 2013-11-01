/*
  Parts of this file are derived from the l7-filter project source
  code (userspace version 0.10), released under the GPL v2 license
  and copyrighted by:

  Ethan Sommer <sommere@users.sf.net> and
  Matthew Strait  <quadong@users.sf.net>, (C) 2006-2007
  http://l7-filter.sf.net
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
/*
#include "../../common/common.h"
#include "../../common/pkt_macros.h"
#include "../../common/apps.h"
*/
#include "../plugin.h"
#include "l7_matcher.h"
#include "l7_config.h"
#include "regex/regex.h"
#include <sys/time.h>
#ifdef FreeBSD
#include "getline.h"
#endif

extern char *name;
char *temp_buffer = NULL;

/*
 * struct pattern
 * contains compiled regular expression + flags to use on matching
 */
typedef struct protocol_t protocol_t;

struct protocol_t {
	int eflags;		// flags for regexec
	int cflags;		// flags for reccomp
	regex_t compiled_regex;
	char *name;		// for logging
	int app_id;		// app code to return on match
	int app_sub_id;		// app subId to return on match
	protocol_t *next;	// next element in linked list
};

/* Prototypes */
static int matches(protocol_t * pattern, const char *buffer);
static void cleanup();
static int hex2dec(char c);
static char *preprocess(const char *s);

#ifdef DEBUG
static void print_payload_dump(const void *s, const struct tct_result * resul);
#endif

/* module private data */
static protocol_t *patterns_head;	// pointer to head of patterns list
static protocol_t *patterns_tail;	// to implement list insertion at the end in costant time


/*
 * Convert packet payload in printable form
 *
 * Return: dynamically allocated string representing the payload content
 */
char *payload_string(u_char *payload, u_int pl_size)
{
	if (pl_size > 256) 
		pl_size = 255;
	char *tmp = malloc((4 * pl_size) + 1);
	u_int i, j;

	/* Substitute all non printable characters with escape sequence '\xXX' */
	for (i = 0, j = 0; i < pl_size; i++) {
		if (isgraph(payload[i])) {
			tmp[j] = (char) payload[i];
			j++;
		} else {
			snprintf(&tmp[j], 5, "\\x%02x", payload[i]);
			j += 4;
		}
	}
	tmp[j] = '\0';

	return tmp;
}



/*
 * create a new pattern and add it to internal linked list
 */
int add_pattern(const char *proto_name, const char *pattern, int eflags,
		int cflags, int app_id, int app_sub_id)
{
	int rc = 0;
	protocol_t *new_pattern = 0;
	char *preprocessed = 0;

	new_pattern = (protocol_t *) calloc(1, sizeof (protocol_t));
	if (new_pattern == 0) {
		fprintf (stderr, "WARNING: Not enough memory. Can't classify %s protocol\n",
		     proto_name);
		return 0;
	}
	new_pattern->name = strdup(proto_name);
	new_pattern->eflags = eflags;
	new_pattern->cflags = cflags;
	new_pattern->app_id = app_id;
	new_pattern->app_sub_id = app_sub_id;
	new_pattern->next = 0;
	preprocessed = preprocess(pattern);
	rc = tct_regcomp(&new_pattern->compiled_regex, preprocessed, cflags);
	free(preprocessed);
	if (rc != 0) {
		fprintf(stderr, "WARNING: Unable to compile regex pattern. Can't classify %s protocol\n",
		     proto_name);
		free(new_pattern->name);
		free(new_pattern);
		return 0;
	}
	// insert at the end
	if (patterns_head == 0) {
		patterns_head = new_pattern;
		patterns_tail = new_pattern;
	} else {
		patterns_tail->next = new_pattern;
		patterns_tail = new_pattern;
	}
	return 1;
}

/*
 * match a pattern against a buffer
 */
int matches(protocol_t * pattern, const char *buffer)
{
	int code;

#ifdef DEBUG
	regmatch_t pmatches;
	code =
	    tct_regexec(&pattern->compiled_regex, buffer, 1, &pmatches,
			pattern->eflags);
#else
	code =
	    tct_regexec(&pattern->compiled_regex, buffer, 0, 0,
			pattern->eflags);
#endif
	if (code == 0)
		return 1;	/* match (1==true) */
	else
		return 0;
}

/*
 * deallocate patterns list
 */
void cleanup()
{
	protocol_t *current = 0;
	while (patterns_head != 0) {
		current = patterns_head;
		patterns_head = patterns_head->next;
		tct_regfree(&current->compiled_regex);
		free(current->name);
		free(current);
	}
}

/*
 * convert an hexadecimal digit to a char code
 */
int hex2dec(char c)
{
	switch (c) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return c - '0';

	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		return c - 'a' + 10;

	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		return c - 'A' + 10;

	default:
		fprintf(stderr, "WARNING: Bad hex digit, %c in regular expression! It could give a false match\n",
		     c);
		return c;
	}
}

/*
 * replace perl-style hex syntax in regular expression
 * with corresponding character
 */
char *preprocess(const char *s)
{
	char *result = (char *) malloc(strlen(s) + 1);
	size_t i = 0, r = 0;
	size_t slen = strlen(s);

	while (i < slen) {
		if ((i + 3 < slen && s[i] == '\\') && (s[i + 1] == 'x')
		    && (isxdigit(s[i + 2])) && isxdigit(s[i + 3])) {
			result[r] = hex2dec(s[i + 2]) * 16 + hex2dec(s[i + 3]);

			switch (result[r]) {
			case '$':
			case '(':
			case ')':
			case '*':
			case '+':
			case '.':
			case '?':
			case '[':
			case ']':
			case '^':
			case '|':
			case '{':
			case '}':
			case '\\':
				fprintf
				    (stderr, "WARNING: regexp contains a regexp control character, %c"
				     ", in hex (\\x%c%c.\nI recommend that you write this as %c"
				     " or \\%c depending on what you meant.\n",
				     result[r], s[i + 2], s[i + 3], result[r],
				     result[r]);
				break;

			case '\0':
				fprintf
				    (stderr, "WARNING: null (\\x00) in layer7 regexp. "
				     "A null terminates the regexp string!\n");
				break;

			default:
				break;
			}
			i += 3;	/* 4 total */
		} else
			result[r] = s[i];

		i++;
		r++;
	}

	result[r] = '\0';

	return result;
}

/*
 * try matching passed buffer to all loaded patterns
 */
void try_match(void *sess, struct tct_result * result)
{
	protocol_t *iterator = 0;
	ptrdiff_t i, j = 0;

	switch (tct_opts.session_type) {
	case SESSION_TYPE_FLOW :{
			struct flow_entry *s = sess;

			for (i = 0, j = 0; i < s->ete->payload_len; ++i) {
				if (s->ete->payload[i] != '\0') {
					temp_buffer[j] = s->ete->payload[i];
					++j;
				}
			}
			break;
		}
	case SESSION_TYPE_BFLOW:{
			const struct bflow_entry *s = sess;

			for (i = 0, j = 0; i < s->ete->payload_len; ++i) {
				if (s->ete->payload[i] != '\0') {
					temp_buffer[j] = s->ete->payload[i];
					++j;
				}
			}
			break;
		}
	}
	temp_buffer[j] = '\0';

	for (iterator = patterns_head; iterator != NULL;
	     iterator = iterator->next) {
		if (matches(iterator, temp_buffer)) {
			result->app_id = iterator->app_id;
			result->sub_id = iterator->app_sub_id;
			result->confidence = 100;	// find a better way to estimate confidence
			SET_BIT(result->flags, CLASS_OUT_NOMORE, 1);
#ifdef DEBUG
			print_payload_dump(sess, result);
#endif
			return;
		}
	}

	/* no match here */
	result->group_id = 0;
	result->sub_id = 0;
	result->confidence = 0;
	SET_BIT(result->flags, CLASS_OUT_REDO, 1);
}

/*
 * read configuration file, load required pattern file
 * and init classifier
 */
bool init_matcher(char *error)
{
	int ret = 1;
	temp_buffer = (char *) malloc(tct_opts.stream_len + 1);
	if (temp_buffer == NULL) {
		strcpy(error,
		       "ERROR: Cannot allocate memory for temporary buffer");
		return false;
	}

	ret = l7_load_config(error);
	return ret;
}

/*
 * cleanup allocated memory and close debug files
 */
void deinit_matcher()
{
	cleanup();
	if (temp_buffer) {
		free(temp_buffer);
		temp_buffer = NULL;
	}
#ifdef DEBUG
	if (l7_config.payload_dump != NULL)
		fclose(l7_config.payload_dump);
#endif				// DEBUG
}

#ifdef  DEBUG

void print_payload_dump(const void *s, const struct tct_result * result)
{
	char *payload;

	if (l7_config.payload_dump == NULL)
		return;

	if (tct_opts.session_type == SESSION_TYPE_FLOW) {
		payload =
		    payload_string(((const struct flow_entry *) s)->ete->payload,
				   ((const struct flow_entry *) s)->ete-> payload_len);
		fprintf(l7_config.payload_dump, "App: %s ", tct_app[result->app_id].app_name);
		if (result->sub_id > 0)
			fprintf(l7_config.payload_dump, "App_sub: %s", 
				tct_app[result->app_id].sub[result->sub_id].sub_name);

		fprintf(l7_config.payload_dump, "\nPayload:%s\n\n", payload);
	} else if (tct_opts.session_type == SESSION_TYPE_BFLOW) {
		payload =
		    payload_string(((const struct bflow_entry *) s)->ete->payload,
				   ((const struct bflow_entry *) s)->ete->payload_len);
		fprintf(l7_config.payload_dump, "App: %s ", tct_app[result->app_id].app_name);
		if (result->sub_id > 0)
			fprintf(l7_config.payload_dump, "App_sub: %s", 
				tct_app[result->app_id].sub[result->sub_id].sub_name);

		fprintf(l7_config.payload_dump, "\nPayload:%s\n\n", payload);
	}

	free(payload);
}

#endif
