/*
 *  src/plugins/l7/l7_config.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include "l7_config.h"
#include "l7_matcher.h"
#include "pat_file_parser.h"
#include "../plugin.h"
#ifdef FreeBSD
#include "getline.h"
#endif

/* constants */
#define CONFIG_FILE "config.txt"
#define PATTERNS_DIR "pats"
#define OPT_NAME_LEN 20
#define OPT_VALUE_LEN 100
#define DEFAULT_MAX_PKTS 1000
#define MAX_SUBDIRS 128
#define MAX_FN_LEN 256

/* globals */
l7_config_options l7_config = { NULL, DEFAULT_MAX_PKTS };

const char *plugin_name = NULL;

/* add_pattern is in l7_matcher.c */
/* prototypes */
static int skip_line(const char *line, size_t len);
static void strip_terminator(char *line);
static int handle_config_line(const char *line, unsigned *proto_num);
static char *find_pattern_file(const char *path, const char *proto_name);
static int add_pattern_from_file(const char *proto_name, const char *path,
				 int app_id, int app_sub_id);

/* skip empty, blank and #-started lines */
int skip_line(const char *line, size_t len)
{
	ptrdiff_t i = 0;
	if ((len == 0) || (line[0] == '#'))
		return 1;

	for (; i < len; ++i)
		if (!isspace(line[i]))
			return 0;
	return 1;
}

/* strip the \n terminator if present */
void strip_terminator(char *line)
{
	char *term = strrchr(line, '\n');
	if (term)
		*term = '\0';
}

/*
* interpret a config line and perform the right action
* return 1 if it successfully loads a signature
*/
int handle_config_line(const char *line, unsigned *proto_num)
{
	char option_name[OPT_NAME_LEN + 1];
	char option_value[OPT_VALUE_LEN + 1];
	char *pat_file = NULL;
	char path[100];
	char *equal = NULL;
	int app_id = 0;
	int app_sub_id = 0;
	int max_packets = 0;
	int ret = 0;
	int read_options;
#ifdef DEBUG
	char file[MAXLINE];
#endif

	equal = strchr(line, '=');
	strncpy(option_name, line, equal - line);
	option_name[equal - line] = '\0';
	read_options =
	    sscanf(equal, "= %s %d %d", option_value, &app_id, &app_sub_id);
	if (read_options == 3) {
		sprintf(path, "%s/plugins/%s/%s", tct_gb.path, plugin_name,
			PATTERNS_DIR);
		pat_file = find_pattern_file(path, option_value);
		ret =
		    add_pattern_from_file(option_value, pat_file, app_id,
					  app_sub_id);
		++(*proto_num);
		free(pat_file);
	} else if (read_options == 1) {
		/* try to get max_packets option */
		if ((strcmp(option_name, "max_packets") == 0)) {
			max_packets = atoi(option_value);
			l7_config.max_packets = max_packets;
		}
//#ifdef DEBUG
#if 0
		/*
		 * search for payload_dump_file option
		 */
		else if (strcmp(option_name, "payload_dump_file") == 0) {
			if (l7_config.payload_dump != NULL) {
				fprintf
				    (stderr, "\nWARNING: payload_dump_file option is give more than once.\n");
			} else {
				/*
				 * open file to store payload dumps.
				 * ignore errors but give a warning
				 */
				snprintf(file, MAXLINE, "output/%s", option_value);
				l7_config.payload_dump = fopen(file, "w");
				if (l7_config.payload_dump == NULL) {
					fprintf(stderr, "\nWARNING: unable to open %s\n",
					       file);
				}
			}
		}
#endif
		else {
			fprintf(stderr, "\nWARNING: unrecognized option %s\n",
			       option_name);
		}
	}

	return ret;
}

/* find proto_name.pat in recursing path */
char *find_pattern_file(const char *path, const char *proto_name)
{
	char filename[MAX_FN_LEN];
	char **subdirs;
	int n = 0;
	FILE *test_fd = NULL;
	DIR *scratchdir;
	struct dirent **namelist;
	int i, d = 1;
	char *ret;

	subdirs = (char **) malloc(MAX_SUBDIRS * sizeof (char *));
	subdirs[0] = "";

	i = scandir(path, &namelist, 0, alphasort);

	if (i < 0) {
		fprintf(stderr, "\nWARNING: Couldn't open %s\n", path);
	} else {
		while (i--) {
			char fulldirname[MAX_FN_LEN];

			snprintf(fulldirname, MAX_FN_LEN, "%s/%s", path,
				 namelist[i]->d_name);

			if ((scratchdir = opendir(fulldirname)) != NULL) {
				closedir(scratchdir);

				if (!strcmp(namelist[i]->d_name, ".")
				    || !strcmp(namelist[i]->d_name, ".."))
					/* do nothing */ ;
				else {
					subdirs[d] =
					    (char *)
					    malloc(strlen(namelist[i]->d_name) +
						   1);
					strcpy(subdirs[d], namelist[i]->d_name);
					++d;
					if (d >= MAX_SUBDIRS - 1) {
						fprintf
						    (stderr, "\nWARNING: Too many subdirectories, skipping the rest!\n");
						break;
					}
				}
			}
			free(namelist[i]);
		}
		free(namelist);
	}

	subdirs[d] = NULL;

	while (subdirs[n] != NULL) {
		int c =
		    snprintf(filename, MAX_FN_LEN, "%s/%s/%s.pat", path,
			     subdirs[n], proto_name);

		if (c > MAX_FN_LEN) {
			fprintf
			    (stderr, "\nWARNING: Filename beginning with %s is too long!\n",
			     filename);
		}

		if (0 != (test_fd = fopen(filename, "r"))) {
			fclose(test_fd);
			ret = malloc(strlen(filename) + 1);
			strcpy(ret, filename);
			return ret;
		}

		++n;
	}

	fprintf(stderr, "\nWARNING: Couldn't find a pattern definition file for %s\n",
	       proto_name);
	return NULL;
}

/* add a pattern to internal list for matching from a file*/
int add_pattern_from_file(const char *proto_name, const char *path, int app_id,
			  int app_sub_id)
{
	int eflags = 0, cflags = 0, ok = 1;
	char *pattern = 0;
	char *basename = 0;

	if (!parse_pattern_file(path, &pattern, &cflags, &eflags)) {
		fprintf(stderr, "\nWARNING: pattern file %s couldn't be load\n", path);
		return 0;
	}

	ok = add_pattern(proto_name, pattern, eflags, cflags, app_id,
			 app_sub_id);
	free(pattern);
	free(basename);
	return ok;
}

int l7_load_config(char *error)
{
	FILE *config = NULL;
	char path[100];
	char *line = NULL;
	size_t line_len = 0;
	size_t read = 0;
	unsigned loaded_proto_num = 0;

	/* attempt to open config file */
	sprintf(path, "%s/plugins/%s/%s", tct_gb.path, plugin_name, CONFIG_FILE);

	if ((config = fopen(path, "r")) == NULL) {
		sprintf(error, "\nERROR: could not read %s", path);
		return 0;
	}

	/* read and decode each line, perform the corresponding action */
	while ((read = getline(&line, &line_len, config) != -1)) {
		if (skip_line(line, read))
			continue;
		strip_terminator(line);
		handle_config_line(line, &loaded_proto_num);
	}
	if (loaded_proto_num == 0) {
		sprintf(error, "\nERROR: No protocol signature loaded");
		return 0;
	} else
		return 1;

}
