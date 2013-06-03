#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= syslog
$(MOD)_SRCS	+= syslog.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
