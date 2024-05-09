/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Andrii Nakryiko */
#ifndef __COMMON_H
#define __COMMON_H

/* packet data*/
struct packet {
	unsigned int ip;
	unsigned char payload[512]; 
	unsigned int prot;
};

#endif /* __COMMON_H */
