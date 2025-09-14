// SPDX-License-Identifier: GPL-2.0-only
/*
 * Shadow stack remap and pivot test using GCS
 *
 * Based on original test logic from:
 *   Copyright (C) 2023 ARM Limited.
 *
 * Modifications and extensions by:
 * 		Author: Igor Svilenkov Bozic <svilenkov@gmail.com>
 */

#include <sys/mman.h>

#include <linux/prctl.h>

#include "kselftest.h"
#include "gcs-util.h"

static size_t page_size = 65536;

static inline int validate_gcs_mode(unsigned long expected_mode)
{
	int ret;
	unsigned long new_mode;

	bool enabling = expected_mode & PR_SHADOW_STACK_ENABLE;

	ret = my_syscall5(__NR_prctl, PR_GET_SHADOW_STACK_STATUS,
				&new_mode, 0, 0, 0);

	if (ret == 0) {
		if (new_mode != expected_mode) {
			ksft_print_msg("Mode set to %lx not %lx\n",
						new_mode, expected_mode);
			ret = -EINVAL;
		}
	} else {
		ksft_print_msg("Failed to validate mode: %d\n", ret);
	}

	if (enabling != chkfeat_gcs()) {
		ksft_print_msg("%senabled by prctl but %senabled in CHKFEAT\n",
					enabling ? "" : "not ",
					chkfeat_gcs() ? "" : "not ");
		ret = -EINVAL;
	}

	return ret;
}

static inline int gcs_set_status(unsigned long mode)
{
	int ret;

	ret = my_syscall5(__NR_prctl, PR_SET_SHADOW_STACK_STATUS, mode,
			  0, 0, 0);

	if (ret == 0) {
		return validate_gcs_mode(mode);
	}

	return ret;
}

static inline __attribute__((always_inline)) int map_one_gcs_page(unsigned long **src)
{
	int elem;
	unsigned long *gcspr;
	elem = (page_size / sizeof(unsigned long)) - 1;
	unsigned long *src_data;

	ksft_print_msg("before __NR_map_shadow_stack %p\n", src);

	/* map one page GCS anywhere (no enable) */
	*src = (void *)my_syscall3(__NR_map_shadow_stack, 0, page_size,
				  SHADOW_STACK_SET_MARKER | SHADOW_STACK_SET_TOKEN);
	src_data = *src;
	ksft_print_msg("__NR_map_shadow_stack returned %p\n", src_data);

	if (*src == MAP_FAILED) {
		ksft_print_msg("map_shadow_stack(%lu) failed: %d\n", page_size, errno);
		return -1;
	}

	gcspr = (unsigned long *)((char *)src_data + page_size - 16);
	ksft_print_msg("GCS mapped starting at=%p .. gcspr=%p\n", src_data, gcspr);

	ksft_print_msg("GCS top = %ld / 8) = %d\n", page_size, elem);
	ksft_print_msg("src[%d] = %lx\n", elem, src_data[elem]);
	ksft_print_msg("src[%d - %d] = %lx\n", elem, 1, src_data[elem - 1]);
	ksft_print_msg("src[%d - %d] = %lx\n", elem, 2, src_data[elem - 2]);

	return elem;
}

static inline __attribute__((always_inline)) unsigned long *remap_vma(unsigned long *src, unsigned long *dst)
{
	int elem;
	unsigned long *remmapped_addr;

	elem = (page_size / sizeof(unsigned long)) - 1;

	ksft_print_msg("mremap: %p -> %p (len=%zu)\n", src, dst, (size_t)page_size);
	remmapped_addr = (void *)my_syscall5(__NR_mremap,
		(unsigned long) src, page_size, page_size,
		MREMAP_MAYMOVE | MREMAP_FIXED,
		(unsigned long) dst);
	ksft_print_msg("dst[%d] = %lx\n", elem, dst[elem]);
	ksft_print_msg("dst[%d - %d] = %lx\n", elem, 1, dst[elem - 1]);
	ksft_print_msg("dst[%d - %d] = %lx\n", elem, 2, dst[elem - 2]);

	if (remmapped_addr == MAP_FAILED) {
		ksft_print_msg("mremap failed errno=%d\n", errno);
		(void) munmap(src, page_size);
		return false;
	}

	ksft_print_msg("mremap moved to %p..%p\n", remmapped_addr, (void *)((unsigned long *)remmapped_addr + page_size));

	return remmapped_addr;
}

static inline __attribute__((always_inline)) unsigned long* get_pivot(unsigned long *remmapped_addr, unsigned long *dst)
{
	int elem;
	elem = (page_size / sizeof(unsigned long)) - 1;

	unsigned long *pivot = (unsigned long *) ((unsigned long)remmapped_addr + page_size - 16);

	ksft_print_msg("pivoting to %p value=0x%lx\n", pivot, *pivot);
	ksft_print_msg("\tret=%p dst=%p\n", remmapped_addr, dst);
	ksft_print_msg("\tdst[%d - %d] = %lx\n", elem, 2, dst[elem - 2]);

	return pivot;
}

static inline __attribute__((always_inline)) bool cap_shadow_stack(unsigned long pivot, unsigned long *remmapped_addr)
{
	unsigned long new_cap;

	pivot -= 8;
	new_cap = (unsigned long) (pivot & GCS_CAP_ADDR_MASK);

	ksft_print_msg("\n");
	ksft_print_msg("cap_shadow_stack(pivot=%lx remapped_addr=%lx):\n", pivot, (unsigned long) remmapped_addr);
	ksft_print_msg("\t(initial) pivot=%lx new_cap=%lx\n", pivot, new_cap);
	ksft_print_msg("\tpivot=%lx new_cap=%lx\n", pivot, new_cap);
	ksft_print_msg("\tGCSSTR %p, %lx\n\n", (unsigned long *) pivot, new_cap);

	gcsstr(pivot, new_cap | 0x01);

	return true;
}

static inline __attribute__((always_inline)) void dump_current_gcspr(void)
{
	unsigned long *curr_gcspr;
	curr_gcspr = get_gcspr();

	ksft_print_msg("====== gcs: dump at GCSPR=%p\n", curr_gcspr);

	for (int i = -4; i <= 1; i++) {
		unsigned long *slot = curr_gcspr + i;
		ksft_print_msg("\t\t[%p] = 0x%lx%s\n",
			slot, *slot,
			(i == 0) ? "   <-- GCSPR" : "");

		if (*slot == 0)
			break;
	}

	ksft_print_msg("\n");
}

static inline __attribute__((always_inline)) void dump_at(unsigned long *addr, int count)
{
	int start, end;
	ksft_print_msg("====== dump at addr=%p\n", addr);

	start = -(count - 1);
	end = 1;

	for (int i = start; i <= end; i++) {
		unsigned long *slot = addr + i;

		ksft_print_msg("\t[slot=%d]\t[%p] = 0x%lx%s\n",
			i, slot, *slot,
			(i == 0) ? "   <-- ADDR" : "");
	}

	ksft_print_msg("\n");
}

static inline __attribute__((always_inline)) void copy_shadow_stack_full(unsigned long curr_base, unsigned long new_base)
{
	ksft_print_msg("copy_shadow_stack_full(curr_base=%lx new_base=%lx):\n", curr_base, new_base);

	for (unsigned long off = 0; off < page_size; off +=8) {
		unsigned long *srcp = (unsigned long *)(curr_base + off);
		unsigned long dst_addr = new_base + off;
		unsigned long val = *srcp;

		if (val != 0) {
			ksft_print_msg("copy off=0x%lx src=%p val=0x%lx -> dst=%lx\n",
				off, srcp, val, dst_addr);

			ksft_print_msg("\tGCSSTR dst=%lx val=%lx\n", dst_addr, val);
		}

		gcsstr((unsigned long)dst_addr, val);
	}
}

static inline __attribute__((always_inline)) void copy_shadow_stack_partial(unsigned long new_base, unsigned long offset)
{
	unsigned long *curr_gcspr;
	unsigned long *new_pivot;

	unsigned long *srcp;
	unsigned long dst_addr;
	unsigned long val;

	ksft_print_msg("copy_shadow_stack_partial(new_base=%lx offset=%lx):\n", new_base, offset);
	curr_gcspr = get_gcspr();

	new_pivot = (unsigned long *)((char *)new_base + offset);
	ksft_print_msg("GCSPR_EL0=%lx new_pivot=%p\n", (unsigned long) curr_gcspr, new_pivot);

	for (long off=0; ; off += 8) {
		srcp = (unsigned long *)((char *)curr_gcspr + off);
		dst_addr = (unsigned long) new_pivot + off;

		ksft_print_msg("[t=%ld] (curr_gcspr + off)=%p dst_addr=%lx\n", off, srcp, dst_addr);
		val = *srcp;

		ksft_print_msg("\tcopy off=0x%lx src=%p val=0x%lx -> dst=%lx (v=%lx)\n", off, srcp, val, dst_addr, *(unsigned long *)dst_addr);
		ksft_print_msg("\tGCSSTR dst=%lx val=%lx\n", dst_addr, val);

		if (val == 0) {
			ksft_print_msg("\tzero encountered in old shadow stack -> so we stop here\n");
			break;
		}

		gcsstr(dst_addr, val);
	}
}

__attribute__((noinline)) int force_bl_ret(int x)
{
	dump_current_gcspr();
	return x + getpid();
}

static inline __attribute__((always_inline)) bool enable_shadow_stack_write()
{
	int s;

	ksft_print_msg("going to try to enable PR_SHADOW_STACK_ENABLE | PR_SHADOW_STACK_WRITE\n");
	s = gcs_set_status(PR_SHADOW_STACK_ENABLE | PR_SHADOW_STACK_WRITE);
	if (s != 0) {
		ksft_print_msg("failed to enable write mode: %d\n", s);
		return false;
	}
	ksft_print_msg("succesfully set PR_SHADOW_STACK_WRITE\n");
	return true;
}

/* Map GCS (while GCS disabled), then try mremap() it and print before/after */
static bool map_and_mremap_no_enable(void)
{
	int elem;
	int pid;
	unsigned long *src, *dst, *shstk;
	unsigned long *curr_gcspr, *pivot, *expected;
	unsigned long curr_base, new_base, offset;
	unsigned long main_ret;

	elem = map_one_gcs_page(&src);
	if (elem == -1)
		return false;

	/* pick a non-overlapping aligned target (two pages forward) */
	dst = (void *)((char *)src + 2 * page_size);
	ksft_print_msg("dst = (src=%p + 2 * page_size) = %p\n", src, dst);
	shstk = remap_vma(src, dst);

	curr_gcspr 	=	get_gcspr();
	curr_base 	=	(unsigned long) curr_gcspr & ~(page_size - 1);
	new_base 	=	(unsigned long) shstk;
	offset 		=	(unsigned long) curr_gcspr - curr_base;
	pivot 		=	get_pivot((unsigned long *)shstk, dst);
	expected 	=	(unsigned long *)((char *)new_base + offset);

	if (pivot != expected) {
		ksft_print_msg("pivot=%p not equal to projected GCSPR=%p", pivot, expected);
		return false;
	}

	if(!enable_shadow_stack_write())
		return false;

	ksft_print_msg(
		"\tcurr_gcspr=%p \n\tcurr_base=0x%lx \n\toffset=0x%lx \n\tproj_gcspr=%p \n\tnew_base=%lx\n",
		curr_gcspr, curr_base, offset, (unsigned long *)((char *)new_base + offset), new_base
	);

	dump_current_gcspr();
	pid = force_bl_ret(0);
	dump_current_gcspr();
	ksft_print_msg("PID = %d\n", pid);

	copy_shadow_stack_full(curr_base, new_base);
	ksft_print_msg("\n");
	copy_shadow_stack_partial((unsigned long)shstk, offset);

	if (!cap_shadow_stack((unsigned long) pivot, (unsigned long *)shstk))
		return false;


	ksft_print_msg("[before GCSSS1 into %p]\n", (pivot));
	dump_at((pivot - 1), 5);
	main_ret = *(pivot);
	ksft_print_msg("about to call GCSSS1 main_ret=%lx\n", main_ret);
	gcsss1(pivot - 1);
	ksft_print_msg("[after GCSSS1]\n");

	dump_at((pivot -1), 5);

	/* hacky way to have a valid RET into the test main function */
	gcsstr((unsigned long) (pivot - 1), main_ret);
	gcsstr((unsigned long) (pivot), 0);

	dump_at((pivot -1), 5);
	return true;
}

typedef bool (*gcs_test)(void);

static struct {
	char *name;
	gcs_test test;
} tests[] = {
	{ "map_and_mremap_no_enable", map_and_mremap_no_enable },
};

int main(void)
{
	int ret;
	ksft_print_header();

	ret = my_syscall5(__NR_prctl,
		PR_SET_SHADOW_STACK_STATUS,
		PR_SHADOW_STACK_ENABLE, 0, 0, 0);

	if (ret != 0)
		ksft_exit_fail_msg("Failed to enable GCS: %d\n", ret);

	dump_current_gcspr();
	ksft_test_result((*tests[0].test)(), "%s\n", tests[0].name);

	ksft_finished();
	return 0;
}
