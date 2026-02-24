/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM deko

#if !defined(_DEKO_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _DEKO_TRACE_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(deko_syscall_entry,
    TP_PROTO(u64 ax, u64 di, u64 si, u64 dx),

    TP_ARGS(ax, di, si, dx),

    TP_STRUCT__entry(
        __field(u64, ax)
        __field(u64, di)
        __field(u64, si)
        __field(u64, dx)
    ),

    TP_fast_assign(
        __entry->ax = ax;
        __entry->di = di;
        __entry->si = si;
        __entry->dx = dx;
    ),

    TP_printk("syscall=%llu di=0x%llx si=0x%llx dx=0x%llx",
              __entry->ax, __entry->di, __entry->si, __entry->dx)
);

TRACE_EVENT(deko_syscall_exit,
	    TP_PROTO(u64 ax, u64 ret),

	    TP_ARGS(ax, ret),

	    TP_STRUCT__entry(__field(u64, ax) __field(u64, ret)),

	    TP_fast_assign(__entry->ax = ax; __entry->ret = ret;),

	    TP_printk("syscall=%llu ret=0x%llx", __entry->ax, __entry->ret)
);

#endif

#include <trace/define_trace.h>
