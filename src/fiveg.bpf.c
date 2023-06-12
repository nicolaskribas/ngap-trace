// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// copied from linux/if_ether.h
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	void *cursor = data;

	// check ethernet frame header and advance the cursor
	if (cursor + sizeof(struct ethhdr) > data_end)
		return 0;
	struct ethhdr *ethh = cursor;
	cursor += sizeof(struct ethhdr);

	if (bpf_ntohs(ethh->h_proto) == ETH_P_IP) {
		// check ip packet header and advance the cursor
		if (cursor + sizeof(struct iphdr) > data_end)
			return 0;
		struct iphdr *iph = cursor;
		cursor += sizeof(struct iphdr);

		if (iph->protocol != IPPROTO_SCTP)
			return 0;

	} else if (bpf_ntohs(ethh->h_proto) == ETH_P_IPV6) {
		// check ipv6 packet header and advance the cursor
		if (cursor + sizeof(struct ipv6hdr) > data_end)
			return 0;
		struct ipv6hdr *ipv6h = cursor;
		cursor += sizeof(struct ipv6hdr);

		if (ipv6h->nexthdr != IPPROTO_SCTP)
			return 0;
	} else {
		return 0;
	}

	// check sctp segment header and advance the cursor
	if (cursor + sizeof(struct sctphdr) > data_end)
		return 0;

	struct sctphdr *sctph = cursor;
	cursor += sizeof(struct sctphdr);

	// check chunk of sctp
	if (cursor + sizeof(struct sctp_chunkhdr) > data_end)
		return 0;

	struct sctp_chunkhdr *chunkh = cursor;
	cursor += sizeof(struct sctp_chunkhdr);

	// we are only interested in data segments
	if (chunkh->type != SCTP_CID_DATA)
		return 0;

	if (cursor + sizeof(struct sctp_datahdr) > data_end)
		return 0;
	struct sctp_datahdr *datah = cursor;
	cursor += sizeof(struct sctp_datahdr);

	// TODO: this is wrong
	ulong data_len =
		chunkh->length - sizeof(struct sctp_chunkhdr) - sizeof(struct sctp_datahdr);
	bpf_printk("ngap packet of size %u", data_len);
	if (cursor + data_len > data_end)
		return 0;
	// TODO: parse ngap packet

	return 0;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	bpf_printk("packet out\n");
	return 0;
}
