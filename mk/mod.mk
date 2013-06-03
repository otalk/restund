#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

$(MOD)_OBJS     := $(patsubst %.c,$(BUILD)/modules/$(MOD)/%.o,$($(MOD)_SRCS))

-include $($(MOD)_OBJS:.o=.d)

$(MOD).so: $($(MOD)_OBJS)
	@echo "  LD [M]  $@"
	@$(LD) $(LFLAGS) $(SH_LFLAGS) $(MOD_LFLAGS) $($(basename $@)_OBJS) \
		$($(basename $@)_LFLAGS) -L$(LIBRE_SO) -lre -o $@

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.c $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk
	@echo "  CC [M]  $@"
	@$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)
