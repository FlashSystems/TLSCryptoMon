// SPDX-License-Identifier: GPL-2.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// Maximum TLS record size per RFC 8446 (5.1.  Record Layer)
// 2^14 = 16384 bytes
static const u16 MAX_TLS_PAYLOAD_SIZE = 16384;

// It is impossible to craft a valid TLS server hello within
// less than 40 bytes.
static const u16 MIN_TLS_PAYLOAD_SIZE = 40;

// Identifier for a TLS_HANDSHAKE_RECORD
static const u8 TLS_HANDSHAKE_RECORD = 0x16;

// TLS version identifiers used. These are encoded in
// network byte order.
static const u16 TLS_LEGACY_VERSION10 = bpf_htons(0x0301);
static const u16 TLS_LEGACY_VERSION12 = bpf_htons(0x0303);

// Identifier for SERVER_HELLO
static const u8 TLS_HST_SERVER_HELLO = 0x02;

// Network-Types we know about
static const u32 AF_INET = 2;
static const u32 AF_INET6 = 10;

// IDs of TLS extensions
static const u8 EXT_KEY_SHARE = 51;

// Global counters for error handling
static u64 ringbuffer_full_counter = 0;
static u64 invalid_packet_counter = 0;

// Simple macro to easily copy an IPv6 address in a way that
// makes the eBPF verifier happy.
#define COPY_IPV6(dst, src) { dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3]; }

// This piece of inline assembly reads any part of a TLS packet by a variable
// offset. It makes sure the read can be tracked by the kernels eBPF verifier.
// Clang often generates code that is not trackable by the verifier leading to
// reads failing. This macro generates a pointer to the given type that can be
// safly dereferenced.
// The code was hand optimized to be traceable by the verifier.
//
// This macro needs an out_of_data label that gets used to bail out if any of
// the range checks fails.
//
// Make sure the scratch parameter have the "+&" prefix or the comparion will be
// nonsense.See https://gcc.gnu.org/onlinedocs/gcc/Modifiers.html for more
// information.
#define GET_VALUE_PTR(type, msg, offset) ({ \
	void* scratch; \
	asm volatile goto ("%[scratch] = %[msg_data]" "\n" \
		"if %[offset] > %[max_header_size] goto %l[out_of_data]" "\n" \
		"%[scratch] += %[offset]" "\n" \
		"%[scratch] += %[type_size]" "\n" \
		"if %[scratch] > %[msg_data_end] goto %l[out_of_data]" "\n" \
		"%[scratch] -= %[type_size]" "\n" \
		: [scratch]"+&r" (scratch), [offset]"+r" (offset) \
		: [msg_data]"r" (msg->data), [msg_data_end]"r" (msg->data_end), [type_size] "X" (sizeof(type)), [max_header_size] "X" (MAX_TLS_PAYLOAD_SIZE) \
		:: out_of_data \
	); \
	(type*)scratch; \
})

// Debug flag
volatile u8 in_const_debug;

// Map that is loaded by the user space program and contains
// the monitored local ports.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u16);
    __uint(value_size, 1);
} in_ports SEC(".maps");

// Define a map that contains the monitored sockets
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(value, u64);
	__type(key, u32);
	__uint(max_entries, 1);
} tls_sockets SEC(".maps");

// Define a socket local storage we can use to store
// the information that we already parsed the header.
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, u8);
} socket_storage SEC(".maps");

// Output structure
typedef struct {
	u32 address_family;	
	u32 remote_address[4];
	u32 local_address[4];
	u16 remote_port;
	u16 local_port;
	u64 ringbuffer_full_counter;
	u64 invalid_packet_counter;
	u16 cipher_suite;
	u16 named_group;
} __attribute__ ((packed)) output_record_t;

// Output ringbuffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024 /* 128 KB */);
} output SEC(".maps");

// Structure of a TLS record header
typedef struct {
	u8 content_type;
	u16 legacy_record_version;
	u16 length;
} __attribute__ ((packed)) tls_message_header_t;

// Sub-Structure below tls_message_header_t for handshake packets.
typedef struct {
	u8 msg_type;
	u8 length[3];
} __attribute__ ((packed)) tls_handshake_header_t;

// Structure of a TLS header
typedef struct {
	tls_message_header_t record_hdr;
	tls_handshake_header_t handshake_hdr;
	u16 server_version;
} __attribute__ ((packed)) tls_header_t;

// Header of a TLS extension
typedef struct {
	u16 type;
	u16 size;
} __attribute__ ((packed)) tls_extension_header_t;

SEC("sockops")
int bpf_socket_operation(struct bpf_sock_ops *ctx)
{
	// Only act on fully created IP-sockets
	if (!ctx->sk) return BPF_OK;
	if (!((ctx->family == AF_INET) || (ctx->family == AF_INET6))) return BPF_OK;

	// Only incomming connections on a socket are further analysed.
	if (ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		u16 local_port = ctx->local_port;
		if (bpf_map_lookup_elem(&in_ports, &local_port)) {
			if (in_const_debug != 0) {
				bpf_printk("New socket monitored. Local port: %d, Remote port: %d", ctx->local_port, bpf_ntohl(ctx->remote_port));
			}

			// Register this socket for monitoring
			u64 key = 0;
			bpf_sock_map_update(ctx, &tls_sockets, &key, BPF_ANY);

			// Clear the socket local storage.
			// The sk != NULL is superflouous because we checked this earlier
			// but we need to do it again to make the eBPF verifier happy.
			struct bpf_sock* sk = ctx->sk;
			if (sk != NULL) bpf_sk_storage_delete(&socket_storage, sk);
		}
	}

	return BPF_OK;
}

bool __always_inline analyse_server_hello(const struct sk_msg_md *msg, const u16 hbo_message_size) {
	output_record_t output_record = {
		.address_family = msg->family,
		.local_port = msg->local_port,
		.remote_port = bpf_ntohl(msg->remote_port),
		.ringbuffer_full_counter = ringbuffer_full_counter,
		.invalid_packet_counter = invalid_packet_counter
	};

	// To save space wihtin the ring buffer we use the same structure for IPv4 and IPv6 addresses.
	switch (output_record.address_family) {
		case AF_INET:
			output_record.local_address[0] = msg->local_ip4;
			output_record.remote_address[0] = msg->remote_ip4;
			break;
		case AF_INET6:
			COPY_IPV6(output_record.local_address, msg->local_ip6);
			COPY_IPV6(output_record.remote_address, msg->remote_ip6);
			break;
	}

	// We're relatively sure we've got a server hello.
	// Now we step thorugh the packet to parse the extension.
	// First we need to skip the random-value (32 byte) and the variable
	// length legacy_session_id_echo.
	u32 offset = sizeof(tls_header_t) + 32 /*random*/;
	offset += *GET_VALUE_PTR(u8, msg, offset) + sizeof(u8);

	// Capture the selected cipher_suite and skip it.
	output_record.cipher_suite = bpf_ntohs(*GET_VALUE_PTR(u16, msg, offset));
	offset += sizeof(u16); /* cipher_suite */

	// Check that the compression method is zero.
	if (*GET_VALUE_PTR(u8, msg, offset) != 0) {
		if (in_const_debug != 0) {
			bpf_printk("Kompression is enabled. This is not allowed for TLS 1.3.");
		}
		goto out_of_data;
	}
	offset += sizeof(u8);

	// The values we want to extract from the extensions.
	output_record.named_group = 0x00;

	// Skip the length field for the extensions property
	offset += sizeof(u16);

	// RFC 8446 defines 22 extensions. We iterate over 32 extension.
	// This should be enough.
	// We have to unroll the loop or the verifier will be verry unhappy.
	#pragma clang loop unroll(full)
	for (u8 i = 0; i < 32; i++) {
		if (msg->data + offset + sizeof(tls_extension_header_t) > msg->data_end) goto out_of_data;
		const tls_extension_header_t* ext_header = GET_VALUE_PTR(tls_extension_header_t, msg, offset);
		offset += sizeof(tls_extension_header_t);

		// Extract the needed information from the key_share extension.
		// Do not modify ppos here, because we use it to skip to the
		// next extension.
		if (in_const_debug != 0) {
			bpf_printk("Extension %u, Length: %u", bpf_ntohs(ext_header->type), bpf_ntohs(ext_header->size));
		}

		if (bpf_ntohs(ext_header->type) == EXT_KEY_SHARE) {
			// Skip the length header and get the named_group value.
			if (msg->data + offset + sizeof(u16) > msg->data_end) goto out_of_data;
			output_record.named_group = bpf_ntohs(*GET_VALUE_PTR(u16, msg, offset));

			// We've gat all we wanted to know. Stop parsing and exit the loop.
			break;
		}

		// Skip to the next extension
		offset += bpf_htons(ext_header->size);

		// If we're at the end of the message. Leave the loop
		if (offset >= hbo_message_size) break;
	}

	if (in_const_debug != 0) {
		bpf_printk("Cipher suite: %u, DH group: %u", output_record.cipher_suite, output_record.named_group);
	}

	if (bpf_ringbuf_output(&output, &output_record, sizeof(output_record), 0) < 0) {
		__sync_fetch_and_add(&ringbuffer_full_counter, 1);
	}

	return true;

	// We we were out of data (one of the range checks failed)
	// return false. This label is also used by the inline assembly.
	out_of_data:
	return false;
}

SEC("sk_msg")
int bpf_stream_parser(struct sk_msg_md *msg)
{
	// Pull in the whole data of this message and make it availabl
	bpf_msg_pull_data(msg, 0, msg->size, 0);

	// If the socket local storage is initialized, we already analysed a
	// handshake on this socket. We wont bother doing it again for performance
	// reasons.
	if (bpf_sk_storage_get(&socket_storage, msg->sk, NULL, 0) != NULL) {
		return SK_PASS;
	}

	// If we don't have enough data to reconstruct the first part of the TLS
	// header we just request more data.
	if (((void*)msg->data_end - (void*)msg->data) < sizeof(tls_header_t)) {
		// There should be at least one byte in this message. We check this byte
		// to verify that this could possibly be a TLS handshake message. If this
		// is not the case. There is no need to bother with getting more bytes.
		// If the first byte is correct, we call sork_bytes to get at least
		// the first part of the TLS header.
		const char* record_type = (char*)msg->data;
		if (((void*)record_type) + sizeof(char) < msg->data_end) {
			if (record_type[0] == TLS_HANDSHAKE_RECORD) {
				bpf_msg_cork_bytes(msg, sizeof(tls_header_t));
			}
		}
	} else {
		// We have to check again that the buffer is big enough to make the
		// eBPF verifier happy. This is not necessary because we alrady
		// know that the buffer is big enough.
		const tls_header_t* p_header = (tls_header_t*)msg->data;
		if (((void*)p_header) + sizeof(tls_header_t) < msg->data_end) {
			const u16 hbo_message_size = bpf_ntohs(p_header->record_hdr.length);

			// Now verify that this is a TLS_SERVER_HELLO.
			if (
				(p_header->record_hdr.content_type == TLS_HANDSHAKE_RECORD) &&
				(p_header->record_hdr.legacy_record_version >= TLS_LEGACY_VERSION10) &&
				(p_header->record_hdr.legacy_record_version <= TLS_LEGACY_VERSION12) &&
				(p_header->server_version == TLS_LEGACY_VERSION12) &&
				(p_header->handshake_hdr.msg_type == TLS_HST_SERVER_HELLO) &&
				(hbo_message_size > MIN_TLS_PAYLOAD_SIZE) && (hbo_message_size <= MAX_TLS_PAYLOAD_SIZE)
			) {
				if (in_const_debug != 0) {
					bpf_printk("Message Size: %lu, Header Size: %u", msg->size, hbo_message_size);
					bpf_printk("Real size: %lu", ((void*)msg->data_end - (void*)msg->data));
				}

				// If we've not got the complete TLS_SERVER_HELLO message, call cork_bytes to
				// wait for more.
				if (msg->size < hbo_message_size) {
					bpf_msg_cork_bytes(msg, hbo_message_size);
				} else {
					if (in_const_debug != 0) {
						bpf_printk("TLS 1.2/1.3 detected. Local port: %u, Remote port: %u", msg->local_port, bpf_ntohl(msg->remote_port));
					}

					if (!analyse_server_hello(msg, hbo_message_size)) {
						__sync_fetch_and_add(&invalid_packet_counter, 1);
					}

					// Add a dummy value to the socket storage to mark this socket as
					// already inspected. This will be reset on the next established
					// connection.
					bpf_sk_storage_get(&socket_storage, msg->sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);
				}
			}
		}
	}

   return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
