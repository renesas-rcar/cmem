/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Renesas IOCTL defines for user cmem drivers;
 *
 * Copyright (C) 2021 by Renesas Electronics Corporation
 *
 * Redistribution of this file is permitted under
 * the terms of the GNU Public License (GPL)
 */
#ifndef _RENESAS_CMEM_H_
#define _RENESAS_CMEM_H_

#define PARAM_SET		1
#define M_LOCK			3
#define M_UNLOCK		4
#define GET_PHYS_ADDR		5
#define M_ALLOCATE		6
#define M_UNALLOCATE		7
#define TRY_CONV		8

#define IOCTL_FROM_DEV_TO_CPU	0
#define IOCTL_FROM_CPU_TO_DEV	1


struct mem_setpara {
	int offset;
	int width;
	int height;
	int stride;
	int tl;
};

struct mem_mlock {
	size_t offset;
	size_t size;
	size_t dir;
};

struct mem_info {
	size_t phys_addr;
};
#endif /* _RENESAS_CMEM_H_ */
