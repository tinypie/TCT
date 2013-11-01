#   Classifiers Makefile
#
#---------------------
include ../options.mk
#---------------------

# Specify here additional OBJECTS needed by this plugin
# need pkt_macros.o
OBJECTS	= l7_matcher.o l7_config.o pat_file_parser.o regex/regex.o

# Specify here additional linker flags needed by this plugin
LDFLAGS +=

# Specify here static libraries needed by this plugin
LIBS	+=

#---------------------
include ../rules.mk
#---------------------

# Specify here custom rules if needed
.SECONDARY: regex/regex.o

regex/regex.o: regex/regex.c
	$(CC) -c $(CFLAGS) -o regex/regex.o regex/regex.c
# EOF
