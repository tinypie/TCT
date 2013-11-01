#ifndef L7_CONFIG_H
#define L7_CONFIG_H

/* stored configuration options */
typedef struct l7_config_options {
	FILE *payload_dump;
	unsigned max_packets;
} l7_config_options;

extern l7_config_options l7_config;
extern const char *plugin_name;

/* load configuration options from file */
extern int l7_load_config(char *error);

#endif	/* L7_CONFIG_H */
