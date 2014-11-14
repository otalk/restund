#
# module.mk
#
# Copyright (C) 2014 &yet LLC
#

MOD		:= influxdb
$(MOD)_SRCS	+= influxdb.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
