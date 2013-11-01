/*
 *  src/plugins/l7/pat_file_parser.c - Component of the TIE v1.0.0-beta3 platform 
 *
 *  Copyright (C) 2007-2011 Alberto Dainotti, Walter de Donato,
 *                            Antonio Pescape', Alessio Botta.
 *  Email: alberto@unina.it, walter.dedonato@unina.it,
 *         pescape@unina.it, a.botta@unina.it 
 *
 *  DIS - Dipartimento di Informatica e Sistemistica (Computer Science Department)
 *  University of Naples Federico II
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
#include "regex/regex.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include "pat_file_parser.h"
#include "l7_config.h"
#ifdef FreeBSD
#include "getline.h"
#endif

/* module constants */
#define PROTOCOL_NAME_MAX_LEN 30
#define FLAGS_MAX_LEN 20

/* states for the parser*/
enum parser_state { PROTOCOL, PATTERN, USERSPACE };

/* module private functions */
static char *base_name(const char *filename);
static int is_comment(const char *line);
static char *get_protocol_name(const char *line);
static char *attribute(const char *line);
static char *value(const char *line);
static int parse_flags(const char *line, int *cflags, int *eflags);

/*
 * Returns the given file name from the last slash to the next dot
 */
char *base_name(const char *filename)
{
	ptrdiff_t i = 0;
	char *last_slash = strrchr(filename, '/');
	char *next_dot = strchr(last_slash, '.');
	char *ret = (char *) malloc(next_dot - last_slash);

	/* take a copy of the filename whitout path and extension */
	for (; i < next_dot - (last_slash + 1); ++i) {
		ret[i] = last_slash[1 + i];
	}
	ret[i] = '\0';
	return ret;
}

/*
 * Returns true if the line (from a pattern file) is a comment
 */
int is_comment(const char *line)
{
	ptrdiff_t i = 0;
	size_t line_len = strlen(line);

	/* blank and #-started lines are comments */
	if ((line_len == 0) || (line[0] == '#'))
		return 1;

	/* lines with only whitespace are comments */
	for (; i < line_len; ++i)
		if (!isspace(line[i]))
			return 0;
	return 1;
}

/*
 * Extracts the protocol name from a line
 * This line should be exactly the name of the file without the .pat extension
 * However, we also allow junk after whitespace
 */
char *get_protocol_name(const char *line)
{
	char *name = (char *) malloc(PROTOCOL_NAME_MAX_LEN + 1);
	size_t line_len = strlen(line);
	ptrdiff_t i = 0;
	for (; i < line_len; ++i) {
		if (!isspace(line[i]))
			name[i] = line[i];
		else
			break;
	}
	name[i] = '\0';
	return name;
}

/*
 * Returns, e.g. "userspace pattern" if the line is "userspace pattern=.*foo"
 */
char *attribute(const char *line)
{
	ptrdiff_t i = 0;
	char *equal = strchr(line, '=');
	char *ret = (char *) malloc(equal - line + 1);

	for (; i < equal - line; ++i) {
		ret[i] = line[i];
	}
	ret[i] = '\0';
	return ret;
}

/*
 * Returns, e.g. ".*foo" if the line is "userspace pattern=.*foo"
 */
char *value(const char *line)
{
	ptrdiff_t i = 0;
	size_t line_len = strlen(line);
	char *equal = strchr(line, '=');
	char *ret = (char *) malloc(&line[line_len] - (equal + 1) + 1);

	for (i = 0; i < &line[line_len] - (equal + 1); ++i) {
		ret[i] = equal[1 + i];
	}
	ret[i] = '\0';
	return ret;
}

/*
 * parse the regexec and regcomp flags
 * Returns 1 on sucess, 0 if any unrecognized flags were encountered
 */
int parse_flags(const char *line, int *cflags, int *eflags)
{
	char flag[FLAGS_MAX_LEN + 1];
	size_t line_len = strlen(line);
	int retOk = 1;
	ptrdiff_t i = 0;
	ptrdiff_t j = 0;

	*cflags = 0;
	*eflags = 0;
	for (i = 0, j = 0; i < line_len; ++i, ++j) {
		if (!isspace(line[i]))
			if (j <= FLAGS_MAX_LEN)	// assume flags are never more than FLAGS_MAX_LEN chars
				flag[j] = line[i];

		if (isspace(line[i]) || (i == line_len - 1)) {
			if (i == line_len - 1)
				j += 1;
			flag[j] = '\0';
			if (strcmp(flag, "REG_EXTENDED") == 0)
				*cflags |= REG_EXTENDED;
			else if (strcmp(flag, "REG_ICASE") == 0)
				*cflags |= REG_ICASE;
			else if (strcmp(flag, "REG_NEWLINE") == 0)
				*cflags |= REG_NEWLINE;
			else if (strcmp(flag, "REG_NOTBOL") == 0)
				*eflags |= REG_NOTBOL;
			else if (strcmp(flag, "REG_NOTEOL") == 0)
				*eflags |= REG_NOTEOL;
			else if ((strcmp(flag, "REG_NOSUB") == 0)) {
				*cflags |= REG_NOSUB;
			} else {
				fprintf
				    (stderr, "WARNING: encountered unknown flag %s in pattern file\n",
				     flag);
				break;
			}
			flag[0] = '\0';
			j = -1;
		}
	}
	return retOk;
}

int parse_pattern_file(const char *filename, char **pattern, int *cflags,
		       int *eflags)
{
	enum parser_state state = PROTOCOL;
	char *name = NULL;
	char *line = NULL;
	size_t line_len = 0;
	size_t actual_line_len = 0;
	char *new_line = NULL;
	char *basename = NULL;
	char *attrib = NULL;
	char *val = NULL;
	int ret_ok = 1;
	FILE *pat_file = NULL;

	pat_file = fopen(filename, "r");

	if (!pat_file) {
		return 0;	/* safe to return here. No allocation yet */
	}

	basename = base_name(filename);

	*cflags = REG_EXTENDED | REG_ICASE
#ifndef DEBUG
	    | REG_NOSUB
#endif				/* DEBUG */
	    ;
	*eflags = 0;

	while ((actual_line_len = getline(&line, &line_len, pat_file) != -1)) {

		if ((actual_line_len == 0) || is_comment(line))
			continue;

		if ((new_line = strrchr(line, '\n')))
			(*new_line) = '\0';

		if (state == PROTOCOL) {
			name = get_protocol_name(line);

			if (strcmp(name, basename) != 0) {
				fprintf
				    (stderr, "WARNING: Protocol declared in file does not match file name.\n"
				     "File name is %s, but the file says %s\n",
				     basename, name);
				ret_ok = 0;
				break;
			}
			state = PATTERN;
			continue;
		}

		if (state == PATTERN) {
			(*pattern) = strdup(line);
			state = USERSPACE;
			continue;
		}

		if (state == USERSPACE) {
			if (!strchr(line, '=')) {
				fprintf
				    (stderr, "WARNING: ignored bad line in pattern file:\n\t%s\n",
				     line);
				continue;
			}

			attrib = attribute(line);
			if (strcmp(attrib, "userspace pattern") == 0) {
				*pattern = value(line);
				free(attrib);
			} else if (strcmp(attrib, "userspace flags") == 0) {
				val = value(line);
				ret_ok &= parse_flags(val, cflags, eflags);
				free(val);
				free(attrib);
				break;
			} else {
				fprintf
				    (stderr, "WARNING: ignored unknown pattern file attribute \"%s\"\n",
				     attrib);
				free(attrib);
			}
		}
	}
	free(name);
	free(basename);
	free(line);
	fclose(pat_file);
	return ret_ok;
}
