#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= turn
$(MOD)_SRCS	+= alloc.c
$(MOD)_SRCS	+= chan.c
$(MOD)_SRCS	+= perm.c
$(MOD)_SRCS	+= turn.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
