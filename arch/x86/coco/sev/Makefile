# SPDX-License-Identifier: GPL-2.0

obj-y += core.o noinstr.o vc-handle.o deko.o

# Experiment-only poller accounting.  This remains absent unless the kernel is
# built with `make DEKO_FEATURES=poller-metrics ...`.
ifneq ($(filter poller-metrics,$(DEKO_FEATURES)),)
CFLAGS_deko.o += -DDEKO_POLLER_METRICS
endif

# Clang 14 and older may fail to respect __no_sanitize_undefined when inlining
UBSAN_SANITIZE_noinstr.o	:= n

# GCC may fail to respect __no_sanitize_address or __no_kcsan when inlining
KASAN_SANITIZE_noinstr.o	:= n
KCSAN_SANITIZE_noinstr.o	:= n

GCOV_PROFILE_noinstr.o		:= n
