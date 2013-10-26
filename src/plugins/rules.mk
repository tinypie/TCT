#   Common Makefile Rules for plug-ins
#
all: head $(PLUGIN) 

.INTERMEDIATE: $(OBJECTS)

# Plugin Shared Object
#%.so: $(OBJECTS) $(INCS)
#	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $<
%.so: %.c $(OBJECTS) $(INCS)
	$(CC) -D 'VERSION="$(VERSION)"' $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $<

# Generic Object
%.o: %.c %.h
	$(CC) -c $(CFLAGS) -o $@ $< $(LIBS)

# Generic Object (without header) 
%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $< $(LIBS)

head:
	@ printf '---------------- Plugin: $(NAME) -----------------\n'

clean:
	@ printf '\t Cleaning $(NAME) plugin folder...\n'
#	@ rm -f *.o
#	@ rm -f $(OBJECTS)  
	@ rm -f $(OBJECTS) *.so 
