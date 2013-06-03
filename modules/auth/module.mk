#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= auth
$(MOD)_SRCS	+= auth.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
