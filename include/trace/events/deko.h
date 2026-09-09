/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM deko

#if !defined(_DEKO_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _DEKO_TRACE_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(deko_syscall_entry, TP_PROTO(u64 ax, u64 di, u64 si, u64 dx),

	    TP_ARGS(ax, di, si, dx),

	    TP_STRUCT__entry(__field(u64, ax) __field(u64, di) __field(u64, si)
				     __field(u64, dx)),

	    TP_fast_assign(__entry->ax = ax; __entry->di = di; __entry->si = si;
			   __entry->dx = dx;),

	    TP_printk("syscall=%llu di=0x%llx si=0x%llx dx=0x%llx", __entry->ax,
		      __entry->di, __entry->si, __entry->dx));

TRACE_EVENT(deko_syscall_exit, TP_PROTO(u64 ax, u64 ret),

	    TP_ARGS(ax, ret),

	    TP_STRUCT__entry(__field(u64, ax) __field(u64, ret)),

	    TP_fast_assign(__entry->ax = ax; __entry->ret = ret;),

	    TP_printk("syscall=%llu ret=0x%llx", __entry->ax, __entry->ret));

TRACE_EVENT(deko_monitor_migration_notified,
	    TP_PROTO(pid_t pid, u64 migration_version),

	    TP_ARGS(pid, migration_version),

	    TP_STRUCT__entry(__field(pid_t, pid)
				     __field(u64, migration_version)),

	    TP_fast_assign(__entry->pid = pid;
			   __entry->migration_version = migration_version;),

	    TP_printk("pid=%d migration_version=%llu", __entry->pid,
		      __entry->migration_version));

TRACE_EVENT(deko_monitor_migration_detected,
	    TP_PROTO(pid_t pid, unsigned int old_cpu, unsigned int new_cpu),

	    TP_ARGS(pid, old_cpu, new_cpu),

	    TP_STRUCT__entry(__field(pid_t, pid) __field(unsigned int, old_cpu)
				     __field(unsigned int, new_cpu)),

	    TP_fast_assign(__entry->pid = pid; __entry->old_cpu = old_cpu;
			   __entry->new_cpu = new_cpu;),

	    TP_printk("pid=%d old_cpu=%u new_cpu=%u", __entry->pid,
		      __entry->old_cpu, __entry->new_cpu));

TRACE_EVENT(deko_timer_service, TP_PROTO(pid_t pid),

	    TP_ARGS(pid),

	    TP_STRUCT__entry(__field(pid_t, pid)),

	    TP_fast_assign(__entry->pid = pid;),

	    TP_printk("pid=%d", __entry->pid));

TRACE_EVENT(deko_eager_paging,
	    TP_PROTO(const char *reason, unsigned long start_addr,
		     unsigned long length, unsigned long prot),

	    TP_ARGS(reason, start_addr, length, prot),

	    TP_STRUCT__entry(__string(reason, reason) __field(unsigned long,
							      start_addr)
				     __field(unsigned long, length)
					     __field(unsigned long, prot)),

	    TP_fast_assign(__assign_str(reason);
			   __entry->start_addr = start_addr;
			   __entry->length = length; __entry->prot = prot;),

	    TP_printk("reason=%s start_addr=0x%lx length=0x%lx prot=0x%lx",
		      __get_str(reason), __entry->start_addr, __entry->length,
		      __entry->prot));

TRACE_EVENT(deko_page_fault_service,
	    TP_PROTO(u32 reason, unsigned long requested_pages,
		     unsigned long resolved_pages, int status, u64 elapsed_ns),

	    TP_ARGS(reason, requested_pages, resolved_pages, status, elapsed_ns),

	    TP_STRUCT__entry(__field(u32, reason)
				     __field(unsigned long, requested_pages)
				     __field(unsigned long, resolved_pages)
				     __field(int, status)
				     __field(u64, elapsed_ns)),

	    TP_fast_assign(__entry->reason = reason;
			   __entry->requested_pages = requested_pages;
			   __entry->resolved_pages = resolved_pages;
			   __entry->status = status;
			   __entry->elapsed_ns = elapsed_ns;),

	    TP_printk("reason=%u requested_pages=%lu resolved_pages=%lu status=%d elapsed_ns=%llu",
		      __entry->reason, __entry->requested_pages,
		      __entry->resolved_pages, __entry->status,
		      __entry->elapsed_ns));

TRACE_EVENT(deko_ring_epoll_wait,
	    TP_PROTO(s32 timeout, s64 result, int status, u64 elapsed_ns),

	    TP_ARGS(timeout, result, status, elapsed_ns),

	    TP_STRUCT__entry(__field(s32, timeout)
				     __field(s64, result)
				     __field(int, status)
				     __field(u64, elapsed_ns)),

	    TP_fast_assign(__entry->timeout = timeout;
			   __entry->result = result;
			   __entry->status = status;
			   __entry->elapsed_ns = elapsed_ns;),

	    TP_printk("timeout=%d result=%lld status=%d elapsed_ns=%llu",
		      __entry->timeout, __entry->result, __entry->status,
		      __entry->elapsed_ns));

/* Optional aggregate timing of Linux service, including blocking waits. */
TRACE_EVENT(deko_ring_service,
	    TP_PROTO(u64 ax, bool from_poller, int status, u64 elapsed_ns),

	    TP_ARGS(ax, from_poller, status, elapsed_ns),

	    TP_STRUCT__entry(__field(u64, ax)
				     __field(bool, from_poller)
				     __field(int, status)
				     __field(u64, elapsed_ns)),

	    TP_fast_assign(__entry->ax = ax;
			   __entry->from_poller = from_poller;
			   __entry->status = status;
			   __entry->elapsed_ns = elapsed_ns;),

	    TP_printk("syscall=%llu from_poller=%d status=%d elapsed_ns=%llu",
		      __entry->ax, __entry->from_poller,
		      __entry->status, __entry->elapsed_ns));

#endif

#include <trace/define_trace.h>
