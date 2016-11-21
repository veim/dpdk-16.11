/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdarg.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>


#include <rte_crypto.h>
#include <rte_cryptodev.h>

#include "rte_port_crypto.h"

#define MAX_PKT_BURST 32


/*
 * Port CRYPTO Reader
 */
#ifdef RTE_PORT_STATS_COLLECT

#define RTE_PORT_CRYPTO_READER_STATS_PKTS_IN_ADD(port, val) \
	port->stats.n_pkts_in += val
#define RTE_PORT_CRYPTO_READER_STATS_PKTS_DROP_ADD(port, val) \
	port->stats.n_pkts_drop += val

#else

#define RTE_PORT_CRYPTO_READER_STATS_PKTS_IN_ADD(port, val)
#define RTE_PORT_CRYPTO_READER_STATS_PKTS_DROP_ADD(port, val)

#endif

struct rte_port_crypto_reader {
	struct rte_port_in_stats stats;

	uint8_t dev_id;
	uint16_t qp_id;

	uint16_t op_burst_sz;

	struct rte_crypto_op *op_buffer[MAX_PKT_BURST];


};

static void *
rte_port_crypto_reader_create(void *params, int socket_id)
{
	struct rte_port_crypto_reader_params *conf =
			(struct rte_port_crypto_reader_params *) params;
	struct rte_port_crypto_reader *port;

	/* Check input parameters */
	if (conf == NULL) {
		RTE_LOG(ERR, PORT, "%s: params is NULL\n", __func__);
		return NULL;
	}

	/* Memory allocation */
	port = rte_zmalloc_socket("port", sizeof(*port),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (port == NULL) {
		RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
		return NULL;
	}

	/* Initialization */
	port->dev_id = conf->dev_id;
	port->qp_id = conf->qp_id;
	port->op_burst_sz = conf->op_burst_sz;

	return port;
}

static int
rte_port_crypto_reader_rx(void *port, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	struct rte_port_crypto_reader *p =
		(struct rte_port_crypto_reader *) port;

	uint16_t nb_rx = 0;
	uint16_t i;

	nb_rx = rte_cryptodev_dequeue_burst(port->dev_id, port->qp_id,
			port->op_buffer, port->op_burst_sz);

	for (i = 0; i < nb_rx; i++) {
		pkts[i] = port->op_buffer[i]->sym->m_src;
		rte_crypto_op_free(port->op_buffer[i]);
	}

	//RTE_PORT_CRYPTO_READER_STATS_PKTS_IN_ADD(p, nb_rx);

	return nb_rx;
}

static int
rte_port_crypto_reader_free(void *port)
{
	if (port == NULL) {
		RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
		return -EINVAL;
	}

	rte_free(port);

	return 0;
}

static int rte_port_crypto_reader_stats_read(void *port,
		struct rte_port_in_stats *stats, int clear)
{
	struct rte_port_crypto_reader *p =
			(struct rte_port_crypto_reader *) port;

	if (stats != NULL)
		memcpy(stats, &p->stats, sizeof(p->stats));

	if (clear)
		memset(&p->stats, 0, sizeof(p->stats));

	return 0;
}



/*
 * Port CRYPTO Writer
 */
#ifdef RTE_PORT_STATS_COLLECT

#define RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(port, val) \
	port->stats.n_pkts_in += val
#define RTE_PORT_CRYPTO_WRITER_STATS_PKTS_DROP_ADD(port, val) \
	port->stats.n_pkts_drop += val

#else

#define RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(port, val)
#define RTE_PORT_CRYPTO_WRITER_STATS_PKTS_DROP_ADD(port, val)

#endif

struct rte_port_crypto_writer {
	struct rte_port_out_stats stats;

	uint8_t dev_id;
	uint16_t qp_id;

	unsigned digest_length;
	uint32_t op_burst_sz;
//	uint64_t bsz_mask

	struct rte_mempool *op_pool;
	struct rte_cryptodev_sym_session *session;

	uint8_t do_cipher;
	uint8_t do_hash;
	uint8_t hash_verify;
	enum rte_crypto_cipher_algorithm cipher_algo;
	enum rte_crypto_auth_algorithm auth_algo;

	enum rte_crypto_op_type op_type;
	struct rte_crypto_op *op_buffer[MAX_PKT_BURST];
	uint16_t nb_ops;
//	uint8_t ec_dc;
//	uint8_t sw_hw;

};

static void *
rte_port_crypto_writer_create(void *params, int socket_id)
{
	struct rte_port_crypto_writer_params *conf =
			(struct rte_port_crypto_writer_params *) params;
	struct rte_port_crypto_writer *port;

	/* Check input parameters */
	if ((conf == NULL) ||
		(conf->ops == NULL)) {
		RTE_LOG(ERR, PORT, "%s: Invalid input parameters\n", __func__);
		return NULL;
	}

	/* Memory allocation */
	port = rte_zmalloc_socket("PORT", sizeof(*port),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (port == NULL) {
		RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
		return NULL;
	}

	/* Initialization */
	port->digest_length = conf->digest_length;
	port->dev_id = conf->dev_id;
	port->qp_id = conf->qp_id;
	port->op_pool = conf->op_pool;
	port->session = conf->session;
	port->op_type = conf->op_type;
	port->do_cipher = conf->do_cipher;
	port->do_hash = conf->do_hash;
	port->hash_verify = conf->hash_verify;
	port->cipher_alg = conf->cipher_alg;
	port->auth_alg = conf->auth_alg;
	port->op_burst_sz = conf->op_burst_sz;
	port->nb_ops = 0;

	return port;
}

static inline void
enqueue_burst(struct rte_port_crypto_writer *p)
{
	uint32_t nb_tx;

	nb_tx = rte_cryptodev_enqueue_burst(p->dev_id, p->qp_id,
			 p->crypto_ops, p->nb_ops);

//	RTE_PORT_ETHDEV_WRITER_STATS_PKTS_DROP_ADD(p, p->nb_ops - nb_tx);
	if (unlikely(nb_tx < p->nb_ops)) {
		//crypto_statistics[port->dev_id].errors += (n - ret);
		do {
			rte_pktmbuf_free(p->op_buffer[nb_tx]->sym->m_src);
			rte_crypto_op_free(p->op_buffer[nb_tx]);
		} while (++nb_tx < p->nb_ops);
	}
	p->nb_ops = 0;
}

static int
rte_port_crypto_writer_tx(void *port, struct rte_mbuf *pkt)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;

	if(port->nb_ops >= port->op_burst_sz)
		return 0;

	port->op_buffer[port->nb_ops++] = rte_crypto_op_alloc(
			port->op_pool, port->op_type);

	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;

	unsigned ipdata_offset, pad_len, data_len;
	char *padding;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	if (eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))
		return -1;

	ipdata_offset = sizeof(struct ether_hdr);

	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
			ipdata_offset);

	ipdata_offset += (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK)
			* IPV4_IHL_MULTIPLIER;

	/* Zero pad data to be crypto'd so it is block aligned */
	data_len  = rte_pktmbuf_data_len(pkt) - ipdata_offset;

	if (port->do_hash && port->hash_verify)
		data_len -= port->digest_length;

	pad_len = data_len % port->block_size ? port->block_size -
			(data_len % port->block_size) : 0;

	if (pad_len) {
		padding = rte_pktmbuf_append(pkt, pad_len);
		if (unlikely(!padding))
			return -1;

		data_len += pad_len;
		memset(padding, 0, pad_len);
	}

	/* Set crypto operation data parameters */
	struct rte_crypto_op *op = port->op_buffer[port->nb_ops - 1];
	rte_crypto_op_attach_sym_session(op, port->session);

	if (port->do_hash) {
		if (!port->hash_verify) {
			/* Append space for digest to end of packet */
			op->sym->auth.digest.data = (uint8_t *)rte_pktmbuf_append(pkt,
					port->digest_length);
		} else {
			op->sym->auth.digest.data = rte_pktmbuf_mtod(pkt,
					uint8_t *) + ipdata_offset + data_len;
		}

		op->sym->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(pkt,
				rte_pktmbuf_pkt_len(pkt) - port->digest_length);
		op->sym->auth.digest.length = port->digest_length;

		/* For wireless algorithms, offset/length must be in bits */
		if (port->auth_algo == RTE_CRYPTO_AUTH_SNOW3G_UIA2 ||
				port->auth_algo == RTE_CRYPTO_AUTH_KASUMI_F9 ||
				port->auth_algo == RTE_CRYPTO_AUTH_ZUC_EIA3) {
			op->sym->auth.data.offset = ipdata_offset << 3;
			op->sym->auth.data.length = data_len << 3;
		} else {
			op->sym->auth.data.offset = ipdata_offset;
			op->sym->auth.data.length = data_len;
		}

		if (port->aad.length) {
			op->sym->auth.aad.data = port->aad.data;
			op->sym->auth.aad.phys_addr = port->aad.phys_addr;
			op->sym->auth.aad.length = port->aad.length;
		}
	}

	if (port->do_cipher) {
		op->sym->cipher.iv.data = port->iv.data;
		op->sym->cipher.iv.phys_addr = port->iv.phys_addr;
		op->sym->cipher.iv.length = port->iv.length;

		/* For wireless algorithms, offset/length must be in bits */
		if (port->cipher_algo == RTE_CRYPTO_CIPHER_SNOW3G_UEA2 ||
				port->cipher_algo == RTE_CRYPTO_CIPHER_KASUMI_F8 ||
				port->cipher_algo == RTE_CRYPTO_CIPHER_ZUC_EEA3) {
			op->sym->cipher.data.offset = ipdata_offset << 3;
			op->sym->cipher.data.length = data_len << 3;
		} else {
			op->sym->cipher.data.offset = ipdata_offset;
			op->sym->cipher.data.length = data_len;
		}
	}

	op->sym->m_src = pkt;

//	qconf = &lcore_queue_conf[lcore_id];
//	len = qconf->op_buf[port->dev_id].len;
//	qconf->op_buf[port->dev_id].buffer[len] = op;
//	len++;

	if (port->nb_ops >= p->op_burst_sz)
		enqueue_burst(port);

	return 0;
}

/*
static int
rte_port_crypto_writer_tx_bulk(void *port,
		struct rte_mbuf **pkts,
		uint64_t pkts_mask)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;

	uint64_t bsz_mask = p->bsz_mask;
	uint32_t nb_ops = p->nb_ops;
	uint64_t expr = (pkts_mask & (pkts_mask + 1)) |
			((pkts_mask & bsz_mask) ^ bsz_mask);

	if (expr == 0) {
//		uint64_t n_pkts = __builtin_popcountll(pkts_mask);
//		uint32_t n_pkts_ok;
//		enum crypto_result ret;
		if (crypto_buf_count)
			enqueue_burst(p);

/*		RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(p, n_pkts);
		ret = crypto_encrypt(p->crypto_buf, p->cipher, p->hasher);
*/
/*		RTE_PORT_CRYPTO_WRITER_STATS_PKTS_DROP_ADD(p, n_pkts - n_pkts_ok);
		for ( ; n_pkts_ok < n_pkts; n_pkts_ok++) {
			struct rte_mbuf *pkt = pkts[n_pkts_ok];

			rte_pktmbuf_free(pkt);
		}
*//*	} else {
		for ( ; pkts_mask; ) {
			uint32_t pkt_index = __builtin_ctzll(pkts_mask);
			uint64_t pkt_mask = 1LLU << pkt_index;
			struct rte_mbuf *pkt = pkts[pkt_index];

			p->crypto_buf[crypto_buf_count++] = pkt;
			RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(p, 1);
			pkts_mask &= ~pkt_mask;
		}

		p->crypto_buf_count = crypto_buf_count;
		if (crypto_buf_count >= p->op_burst_sz)
			process_burst(p);
	}

	return 0;
}
*/

static int
rte_port_crypto_writer_flush(void *port)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;

	if (p->crypto_buf_count > 0)
		enqueue_burst(p);

	return 0;
}

static int
rte_port_crypto_writer_free(void *port)
{
	if (port == NULL) {
		RTE_LOG(ERR, PORT, "%s: Port is NULL\n", __func__);
		return -EINVAL;
	}

	rte_port_crypto_writer_flush(port);
	rte_free(port);

	return 0;
}

static int rte_port_crypto_writer_stats_read(void *port,
		struct rte_port_out_stats *stats, int clear)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;

	if (stats != NULL)
		memcpy(stats, &p->stats, sizeof(p->stats));

	if (clear)
		memset(&p->stats, 0, sizeof(p->stats));

	return 0;
}



/*
 * Summary of port operations
 */
struct rte_port_in_ops rte_port_crypto_reader_ops = {
	.f_create = rte_port_crypto_reader_create,
	.f_free = rte_port_crypto_reader_free,
	.f_rx = rte_port_crypto_reader_rx,
	.f_stats = rte_port_crypto_reader_stats_read,
};

struct rte_port_out_ops rte_port_crypto_writer_ops = {
	.f_create = rte_port_crypto_writer_create,
	.f_free = rte_port_crypto_writer_free,
	.f_tx = rte_port_crypto_writer_tx,
	.f_tx_bulk = NULL,//rte_port_crypto_writer_tx_bulk,
	.f_flush = rte_port_crypto_writer_flush,
	.f_stats = rte_port_crypto_writer_stats_read,
};
