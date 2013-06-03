#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= status
$(MOD)_SRCS	+= status.c
$(MOD)_SRCS	+= httpd.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
