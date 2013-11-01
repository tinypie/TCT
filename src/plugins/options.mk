# common Makefile options for plugins

#  Static option
OPT = -g  -DSUPPORT_IPV6 #-DDEBUG

# Generate position-independent code (PIC) suitable for use in a shared library.
ifdef fpic
	OPT += -fPIC
endif

#  which compliler
CC = gcc

#  options for development
CFLAGS = -Wall -Winline $(OPT)

INCS	= ../plugin.h
LDFLAGS	= -shared -nostartfiles		# -shared should with -fpic
NAME	= $(shell name=`pwd` && echo $${name\#\#*/})
PLUGIN	= class_$(NAME).so
VERSION	= $(shell cat VERSION)

#EOF
