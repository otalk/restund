#
# module.mk
#
# Copyright (C) 2014 &yet LLC
#

MOD		:= cpuusage
$(MOD)_SRCS	+= cpuusage.c
$(MOD)_LFLAGS	+= -lm

include mk/mod.mk
