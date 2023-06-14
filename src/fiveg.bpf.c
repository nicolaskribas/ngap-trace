// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// copied from linux/if_ether.h
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

#define MAX_CHUNKS 128

// Create a pointer to a struct, points it to the current cursor position
// and then advances the cursor by the size of the struct.
#define ADVANCE_CURSOR(TYPE, NAME, CURSOR, END) \
	if (CURSOR + sizeof(TYPE) > END)        \
		return 0;                       \
	TYPE *NAME = CURSOR;                    \
	CURSOR += sizeof(TYPE)

#define MOUNT(TYPE, NAME, CURSOR, END)   \
	if (CURSOR + sizeof(TYPE) > END) \
		return 0;                \
	TYPE *NAME = CURSOR;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	void *cursor = data;

	// FIXME: here we assume it is an ethernet frame inside the socket buffer
	ADVANCE_CURSOR(struct ethhdr, ethh, cursor, data_end);

	__u8 ip_proto;

	switch (bpf_ntohs(ethh->h_proto)) {
	case ETH_P_IP:
		ADVANCE_CURSOR(struct iphdr, iph, cursor, data_end);
		ip_proto = iph->protocol;
		break;

	case ETH_P_IPV6:
		ADVANCE_CURSOR(struct ipv6hdr, ipv6h, cursor, data_end);
		ip_proto = ipv6h->nexthdr;
		break;

	default:
		return 0;
	}

	if (ip_proto != IPPROTO_SCTP)
		return 0;

	ADVANCE_CURSOR(struct sctphdr, sctph, cursor, data_end);

	for (int i = 0; i < MAX_CHUNKS; i++) {
		MOUNT(struct sctp_chunkhdr, chunkh, cursor, data_end);
		__u16 chunk_len = bpf_ntohs(chunkh->length);

		if (chunkh->type == SCTP_CID_DATA) {
			MOUNT(struct sctp_datahdr, datah, cursor + sizeof(struct sctp_chunkhdr),
			      data_end);
			__u16 payload_len = chunk_len - (sizeof(struct sctp_chunkhdr) +
							 sizeof(struct sctp_datahdr));

			bpf_printk("Received SCTP data packet!");
			// TODO: here, use the sctp payload
		}

		// take into account the padding before advancing the cursor
		chunk_len += (chunk_len % 4) == 0 ? 0 : 4 - chunk_len % 4;
		// work around to a BPF verifier corner case, see: https://stackoverflow.com/questions/70729664/need-help-in-xdp-program-failing-to-load-with-error-r7-offset-is-outside-of-the
		if (chunk_len > 512)
			return 0;
		cursor += chunk_len;
	}

	return 0;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	return 0;
}
