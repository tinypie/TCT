# build plugins in the subdirectorys.


FILE = ../config/enabled_plugins
PLUGINS	= $(shell cut -d "\#" -f1 $(FILE) | sort | uniq)

all:tct_plugin

tct_plugin:
	@ if [ "$(PLUGINS)" ]; then \
		printf '\n*------------------------------------------------*\n';\
		printf 'Building plugin modules\n';\
		printf '*------------------------------------------------*\n'; \
	fi
	@ for plugdir in $(PLUGINS); do \
		if [ -d $$plugdir ]; then \
			$(MAKE) -C $$plugdir --no-print-directory; \
		fi; \
	done

clean:
	@ printf "    clean plugins ...\n"
	@ rm -f *.o
	@ for plugdir in $(PLUGINS); do \
		if [ -d $$plugdir ]; then \
			$(MAKE) -C $$plugdir --no-print-directory clean; \
		fi; \
	done
#EOF
#	@ for plugdir in `ls -l -d */ | cut -d "/" -f1` ; do \
#		$(MAKE) -C $$plugdir --no-print-directory clean; \
