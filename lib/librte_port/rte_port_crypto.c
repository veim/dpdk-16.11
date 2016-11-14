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

#define CPA_CY_SYM_DP_TMP_WORKAROUND 1

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym_dp.h"
#include "cpa_cy_common.h"
#include "cpa_cy_im.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"


#include "rte_port_crypto.h"


/* CIPHER KEY LENGTHS */
#define KEY_SIZE_64_IN_BYTES	(64 / 8)
#define KEY_SIZE_56_IN_BYTES	(56 / 8)
#define KEY_SIZE_128_IN_BYTES	(128 / 8)
#define KEY_SIZE_168_IN_BYTES	(168 / 8)
#define KEY_SIZE_192_IN_BYTES	(192 / 8)
#define KEY_SIZE_256_IN_BYTES	(256 / 8)

/* HMAC AUTH KEY LENGTHS */
#define AES_XCBC_AUTH_KEY_LENGTH_IN_BYTES	(128 / 8)
#define SHA1_AUTH_KEY_LENGTH_IN_BYTES		(160 / 8)
#define SHA224_AUTH_KEY_LENGTH_IN_BYTES		(224 / 8)
#define SHA256_AUTH_KEY_LENGTH_IN_BYTES		(256 / 8)
#define SHA384_AUTH_KEY_LENGTH_IN_BYTES		(384 / 8)
#define SHA512_AUTH_KEY_LENGTH_IN_BYTES		(512 / 8)
#define MD5_AUTH_KEY_LENGTH_IN_BYTES		(128 / 8)
#define KASUMI_AUTH_KEY_LENGTH_IN_BYTES		(128 / 8)

/* HASH DIGEST LENGHTS */
#define AES_XCBC_DIGEST_LENGTH_IN_BYTES		(128 / 8)
#define AES_XCBC_96_DIGEST_LENGTH_IN_BYTES	(96 / 8)
#define MD5_DIGEST_LENGTH_IN_BYTES		(128 / 8)
#define SHA1_DIGEST_LENGTH_IN_BYTES		(160 / 8)
#define SHA1_96_DIGEST_LENGTH_IN_BYTES		(96 / 8)
#define SHA224_DIGEST_LENGTH_IN_BYTES		(224 / 8)
#define SHA256_DIGEST_LENGTH_IN_BYTES		(256 / 8)
#define SHA384_DIGEST_LENGTH_IN_BYTES		(384 / 8)
#define SHA512_DIGEST_LENGTH_IN_BYTES		(512 / 8)
#define KASUMI_DIGEST_LENGTH_IN_BYTES		(32 / 8)

#define IV_LENGTH_16_BYTES	(16)
#define IV_LENGTH_8_BYTES	(8)


/*
 * rte_memzone is used to allocate physically contiguous virtual memory.
 * In this application we allocate a single block and divide between variables
 * which require a virtual to physical mapping for use by the QAT driver.
 * Virt2phys is only performed during initialisation and not on the data-path.
 */

#define LCORE_MEMZONE_SIZE	(1 << 22)

struct lcore_memzone
{
	const struct rte_memzone *memzone;
	void *next_free_address;
};

/*
 * Size the qa software response queue.
 * Note: Head and Tail are 8 bit, therefore, the queue is
 * fixed to 256 entries.
 */
#define CRYPTO_SOFTWARE_QUEUE_SIZE 256

struct qa_callbackQueue {
	uint8_t head;
	uint8_t tail;
	uint16_t numEntries;
	struct rte_mbuf *qaCallbackRing[CRYPTO_SOFTWARE_QUEUE_SIZE];
};

struct qa_core_conf {
	CpaCySymDpSessionCtx *encryptSessionHandleTbl[NUM_CRYPTO][NUM_HMAC];
	CpaCySymDpSessionCtx *decryptSessionHandleTbl[NUM_CRYPTO][NUM_HMAC];
	CpaInstanceHandle instanceHandle;
	struct qa_callbackQueue callbackQueue;
	uint64_t qaOutstandingRequests;
	uint64_t numResponseAttempts;
	uint8_t kickFreq;
	void *pPacketIV;
	CpaPhysicalAddr packetIVPhy;
	struct lcore_memzone lcoreMemzone;
} __rte_cache_aligned;

#define MAX_CORES   (RTE_MAX_LCORE)

//static struct qa_core_conf qaCoreConf[MAX_CORES];

/*
 *Create maximum possible key size,
 *One for cipher and one for hash
 */
struct glob_keys {
	uint8_t cipher_key[32];
	uint8_t hash_key[64];
	uint8_t iv[16];
};

struct glob_keys g_crypto_hash_keys = {
	.cipher_key = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
		0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
		0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20},
	.hash_key = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
		0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
		0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
		0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
		0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x39,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50},
	.iv = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10}
};

/*
 * Offsets from the start of the packet.
 *
 */
#define PACKET_DATA_START_PHYS(p) \
		((p)->buf_physaddr + (p)->data_off)

/*
 * A fixed offset to where the crypto is to be performed, which is the first
 * byte after the Ethernet(14 bytes) and IPv4 headers(20 bytes)
 */
#define CRYPTO_START_OFFSET		(14+20)
#define HASH_START_OFFSET		(14+20)
#define CIPHER_BLOCK_DEFAULT_SIZE	(16)
#define HASH_BLOCK_DEFAULT_SIZE		(16)

/*
 * Offset to the opdata from the start of the data portion of packet.
 * Assumption: The buffer is physically contiguous.
 * +18 takes this to the next cache line.
 */

#define CRYPTO_OFFSET_TO_OPDATA		(ETHER_MAX_LEN+18)

/*
 * Default number of requests to place on the hardware ring before kicking the
 * ring pointers.
 */
#define CRYPTO_BURST_TX	(16)

/*
 * Only call the qa poll function when the number responses in the software
 * queue drops below this number.
 */
#define CRYPTO_QUEUED_RESP_POLL_THRESHOLD	(32)

/*
 * Limit the number of polls per call to get_next_response.
 */
#define GET_NEXT_RESPONSE_FREQ	(32)

/*
 * Max number of responses to pull from the qa in one poll.
 */
#define CRYPTO_MAX_RESPONSE_QUOTA \
		(CRYPTO_SOFTWARE_QUEUE_SIZE-CRYPTO_QUEUED_RESP_POLL_THRESHOLD-1)

#if (CRYPTO_QUEUED_RESP_POLL_THRESHOLD + CRYPTO_MAX_RESPONSE_QUOTA >= \
		CRYPTO_SOFTWARE_QUEUE_SIZE)
#error Its possible to overflow the qa response Q with current poll and \
		response quota.
#endif



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

	uint32_t socket_id;
	uint32_t lcore_id;
	uint8_t port_id;
	uint8_t ec_dc;

	CpaCySymDpSessionCtx *encryptSessionHandleTbl[NUM_CRYPTO][NUM_HMAC];
	CpaCySymDpSessionCtx *decryptSessionHandleTbl[NUM_CRYPTO][NUM_HMAC];
	CpaInstanceHandle instanceHandle;
	struct qa_callbackQueue callbackQueue;
	uint64_t qaOutstandingRequests;
	uint64_t numResponseAttempts;
	uint8_t kickFreq;
	void *pPacketIV;
	CpaPhysicalAddr packetIVPhy;
	struct lcore_memzone lcoreMemzone;

	struct qa_callbackQueue callbackQ;
};

static struct rte_port_crypto_reader *crypto_readers[MAX_CORES];


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

	struct rte_mbuf *crypto_buf[2 * RTE_PORT_IN_BURST_SIZE_MAX];
	uint32_t crypto_burst_sz;
	uint16_t crypto_buf_count;
	uint64_t bsz_mask;

	uint32_t socket_id;
	uint32_t lcore_id;
	uint8_t port_id;
	uint8_t ec_dc;

	enum cipher_alg cipher;
	enum hash_alg hasher;

	CpaCySymDpSessionCtx *encryptSessionHandleTbl[NUM_CRYPTO][NUM_HMAC];
	CpaCySymDpSessionCtx *decryptSessionHandleTbl[NUM_CRYPTO][NUM_HMAC];
	CpaInstanceHandle instanceHandle;
	struct qa_callbackQueue callbackQueue;
	uint64_t qaOutstandingRequests;
	uint64_t numResponseAttempts;
	uint8_t kickFreq;
	void *pPacketIV;
	CpaPhysicalAddr packetIVPhy;
	struct lcore_memzone lcoreMemzone;

	struct qa_callbackQueue callbackQ;
};

static struct rte_port_crypto_writer *crypto_writers[MAX_CORES];


static void
crypto_callback(CpaCySymDpOpData *pOpData,
		__rte_unused CpaStatus status,
		__rte_unused CpaBoolean verifyResult)
{
	uint32_t lcore_id;
	lcore_id = rte_lcore_id();

	struct qa_callbackQueue *callbackQ =
		&(crypto_writers[lcore_id]->callbackQueue);

	/*
	 * Received a completion from the QA hardware.
	 * Place the response on the return queue.
	 */
	callbackQ->qaCallbackRing[callbackQ->head] = pOpData->pCallbackTag;
	callbackQ->head++;
	callbackQ->numEntries++;
	crypto_writers[lcore_id]->qaOutstandingRequests--;
}

static void
qa_crypto_callback(CpaCySymDpOpData *pOpData, CpaStatus status,
		CpaBoolean verifyResult)
{
	crypto_callback(pOpData, status, verifyResult);
}

/*
 * Each allocation from a particular memzone lasts for the life-time of
 * the application. No freeing of previous allocations will occur.
 */
static void *
alloc_memzone_region(uint32_t length, struct rte_port_crypto_writer *p)
{
	char *current_free_addr_ptr = NULL;
	struct lcore_memzone *lcore_memzone = &(p->lcoreMemzone);

	current_free_addr_ptr  = lcore_memzone->next_free_address;

	if (current_free_addr_ptr + length >=
		(char *)lcore_memzone->memzone->addr + lcore_memzone->memzone->len) {
		printf("Crypto: No memory available in memzone\n");
		return NULL;
	}
	lcore_memzone->next_free_address = current_free_addr_ptr + length;

	return (void *)current_free_addr_ptr;
}

/*
 * Virtual to Physical Address translation is only executed during initialization
 * and not on the data-path.
 */
static CpaPhysicalAddr
qa_v2p(void *ptr)
{
	const struct rte_memzone *memzone = NULL;
	uint32_t lcore_id = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		memzone = crypto_writers[lcore_id]->lcoreMemzone.memzone;

		if ((char*) ptr >= (char *) memzone->addr &&
				(char*) ptr < ((char*) memzone->addr + memzone->len)) {
			return (CpaPhysicalAddr)
					(memzone->phys_addr + ((char *) ptr - (char*) memzone->addr));
		}
	}
	printf("Crypto: Corresponding physical address not found in memzone\n");
	return (CpaPhysicalAddr) 0;
}

static CpaStatus
getCoreAffinity(Cpa32U *coreAffinity, const CpaInstanceHandle instanceHandle)
{
	CpaInstanceInfo2 info;
	Cpa16U i = 0;
	CpaStatus status = CPA_STATUS_SUCCESS;

	memset(&info, 0, sizeof(CpaInstanceInfo2));

	status = cpaCyInstanceGetInfo2(instanceHandle, &info);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: Error getting instance info\n");
		return CPA_STATUS_FAIL;
	}
	for (i = 0; i < MAX_CORES; i++) {
		if (CPA_BITMAP_BIT_TEST(info.coreAffinity, i)) {
			*coreAffinity = i;
			return CPA_STATUS_SUCCESS;
		}
	}
	return CPA_STATUS_FAIL;
}

static CpaStatus
get_crypto_instance_on_core(CpaInstanceHandle *pInstanceHandle,
		uint32_t lcore_id)
{
	Cpa16U numInstances = 0, i = 0;
	CpaStatus status = CPA_STATUS_FAIL;
	CpaInstanceHandle *pLocalInstanceHandles = NULL;
	Cpa32U coreAffinity = 0;

	status = cpaCyGetNumInstances(&numInstances);
	if (CPA_STATUS_SUCCESS != status || numInstances == 0) {
		return CPA_STATUS_FAIL;
	}

	pLocalInstanceHandles = rte_malloc("pLocalInstanceHandles",
			sizeof(CpaInstanceHandle) * numInstances, RTE_CACHE_LINE_SIZE);

	if (NULL == pLocalInstanceHandles) {
		return CPA_STATUS_FAIL;
	}
	status = cpaCyGetInstances(numInstances, pLocalInstanceHandles);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: cpaCyGetInstances failed with status: %"PRId32"\n", status);
		rte_free((void *) pLocalInstanceHandles);
		return CPA_STATUS_FAIL;
	}

	for (i = 0; i < numInstances; i++) {
		status = getCoreAffinity(&coreAffinity, pLocalInstanceHandles[i]);
		if (CPA_STATUS_SUCCESS != status) {
			rte_free((void *) pLocalInstanceHandles);
			return CPA_STATUS_FAIL;
		}
		if (coreAffinity == lcore_id) {
			printf("Crypto: instance found on core %d\n", i);
			*pInstanceHandle = pLocalInstanceHandles[i];
			return CPA_STATUS_SUCCESS;
		}
	}
	/* core affinity not found */
	rte_free((void *) pLocalInstanceHandles);
	return CPA_STATUS_FAIL;
}

static CpaStatus
initCySymSession(const int pkt_cipher_alg,
		const int pkt_hash_alg, const CpaCySymHashMode hashMode,
		const CpaCySymCipherDirection crypto_direction,
		CpaCySymSessionCtx **ppSessionCtx,
		const CpaInstanceHandle cyInstanceHandle,
		struct rte_port_crypto_writer *p)
{
	Cpa32U sessionCtxSizeInBytes = 0;
	CpaStatus status = CPA_STATUS_FAIL;
	CpaBoolean isCrypto = CPA_TRUE, isHmac = CPA_TRUE;
	CpaCySymSessionSetupData sessionSetupData;

	memset(&sessionSetupData, 0, sizeof(CpaCySymSessionSetupData));

	/* Assumption: key length is set to each algorithm's max length */
	switch (pkt_cipher_alg) {
	case NO_CIPHER:
		isCrypto = CPA_FALSE;
		break;
	case CIPHER_DES:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_DES_ECB;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_64_IN_BYTES;
		break;
	case CIPHER_DES_CBC:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_DES_CBC;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_64_IN_BYTES;
		break;
	case CIPHER_DES3:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_3DES_ECB;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_192_IN_BYTES;
		break;
	case CIPHER_DES3_CBC:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_3DES_CBC;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_192_IN_BYTES;
		break;
	case CIPHER_AES:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_AES_ECB;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_128_IN_BYTES;
		break;
	case CIPHER_AES_CBC_128:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_AES_CBC;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_128_IN_BYTES;
		break;
	case CIPHER_KASUMI_F8:
		sessionSetupData.cipherSetupData.cipherAlgorithm =
				CPA_CY_SYM_CIPHER_KASUMI_F8;
		sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
				KEY_SIZE_128_IN_BYTES;
		break;
	default:
		printf("Crypto: Undefined Cipher specified\n");
		break;
	}
	/* Set the cipher direction */
	if (isCrypto) {
		sessionSetupData.cipherSetupData.cipherDirection = crypto_direction;
		sessionSetupData.cipherSetupData.pCipherKey =
				g_crypto_hash_keys.cipher_key;
		sessionSetupData.symOperation = CPA_CY_SYM_OP_CIPHER;
	}

	/* Setup Hash common fields */
	switch (pkt_hash_alg) {
	case NO_HASH:
		isHmac = CPA_FALSE;
		break;
	case HASH_AES_XCBC:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_XCBC;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				AES_XCBC_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_AES_XCBC_96:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_XCBC;
				sessionSetupData.hashSetupData.digestResultLenInBytes =
				AES_XCBC_96_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_MD5:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_MD5;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				MD5_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_SHA1:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				SHA1_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_SHA1_96:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				SHA1_96_DIGEST_LENGTH_IN_BYTES;
	    break;
	case HASH_SHA224:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA224;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				SHA224_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_SHA256:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				SHA256_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_SHA384:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA384;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				SHA384_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_SHA512:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA512;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				SHA512_DIGEST_LENGTH_IN_BYTES;
		break;
	case HASH_KASUMI_F9:
		sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_KASUMI_F9;
		sessionSetupData.hashSetupData.digestResultLenInBytes =
				KASUMI_DIGEST_LENGTH_IN_BYTES;
		break;
	default:
		printf("Crypto: Undefined Hash specified\n");
		break;
	}
	if (isHmac) {
		sessionSetupData.hashSetupData.hashMode = hashMode;
		sessionSetupData.symOperation = CPA_CY_SYM_OP_HASH;
		/* If using authenticated hash setup key lengths */
		if (CPA_CY_SYM_HASH_MODE_AUTH == hashMode) {
			/* Use a common max length key */
			sessionSetupData.hashSetupData.authModeSetupData.authKey =
					g_crypto_hash_keys.hash_key;
			switch (pkt_hash_alg) {
			case HASH_AES_XCBC:
			case HASH_AES_XCBC_96:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						AES_XCBC_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_MD5:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						SHA1_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_SHA1:
			case HASH_SHA1_96:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						SHA1_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_SHA224:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						SHA224_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_SHA256:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						SHA256_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_SHA384:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						SHA384_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_SHA512:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						SHA512_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			case HASH_KASUMI_F9:
				sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
						KASUMI_AUTH_KEY_LENGTH_IN_BYTES;
				break;
			default:
				printf("Crypto: Undefined Hash specified\n");
				return CPA_STATUS_FAIL;
			}
		}
	}

	/* Only high priority supported */
	sessionSetupData.sessionPriority = CPA_CY_PRIORITY_HIGH;

	/* If chaining algorithms */
	if (isCrypto && isHmac) {
		sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
		/* @assumption Alg Chain order is cipher then hash for encrypt
		 * and hash then cipher then has for decrypt*/
		if (CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT == crypto_direction) {
			sessionSetupData.algChainOrder =
					CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
		} else {
			sessionSetupData.algChainOrder =
					CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
		}
	}
	if (!isCrypto && !isHmac) {
		*ppSessionCtx = NULL;
		return CPA_STATUS_SUCCESS;
	}

	/* Set flags for digest operations */
	sessionSetupData.digestIsAppended = CPA_FALSE;
	sessionSetupData.verifyDigest = CPA_TRUE;

	/* Get the session context size based on the crypto and/or hash operations*/
	status = cpaCySymDpSessionCtxGetSize(cyInstanceHandle, &sessionSetupData,
			&sessionCtxSizeInBytes);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: cpaCySymDpSessionCtxGetSize error, status: %"PRId32"\n",
				status);
		return CPA_STATUS_FAIL;
	}

	*ppSessionCtx = alloc_memzone_region(sessionCtxSizeInBytes, p);
	if (NULL == *ppSessionCtx) {
		printf("Crypto: Failed to allocate memory for Session Context\n");
		return CPA_STATUS_FAIL;
	}

	status = cpaCySymDpInitSession(cyInstanceHandle, &sessionSetupData,
			*ppSessionCtx);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: cpaCySymDpInitSession failed with status %"PRId32"\n", status);
		return CPA_STATUS_FAIL;
	}
	return CPA_STATUS_SUCCESS;
}

static CpaStatus
initSessionDataTables(struct rte_port_crypto_writer *p)
{
	Cpa32U i = 0, j = 0;
	CpaStatus status = CPA_STATUS_FAIL;
	for (i = 0; i < NUM_CRYPTO; i++) {
		for (j = 0; j < NUM_HMAC; j++) {
			if (((i == CIPHER_KASUMI_F8) && (j != NO_HASH) && (j != HASH_KASUMI_F9)) ||
				((i != NO_CIPHER) && (i != CIPHER_KASUMI_F8) && (j == HASH_KASUMI_F9)))
				continue;
			status = initCySymSession(i, j, CPA_CY_SYM_HASH_MODE_AUTH,
					CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
					&p->encryptSessionHandleTbl[i][j],
					p->instanceHandle,
					p);

			if (CPA_STATUS_SUCCESS != status) {
				printf("Crypto: Failed to initialize Encrypt sessions\n");
				return CPA_STATUS_FAIL;
			}
			status = initCySymSession(i, j, CPA_CY_SYM_HASH_MODE_AUTH,
					CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT,
					&p->decryptSessionHandleTbl[i][j],
					p->instanceHandle,
					p);
			if (CPA_STATUS_SUCCESS != status) {
				printf("Crypto: Failed to initialize Decrypt sessions\n");
				return CPA_STATUS_FAIL;
			}
		}
	}
	return CPA_STATUS_SUCCESS;
}

int
crypto_init(void)
{
	if (CPA_STATUS_SUCCESS != icp_sal_userStartMultiProcess("SSL",CPA_FALSE)) {
		printf("Crypto: Could not start sal for user space\n");
		return CPA_STATUS_FAIL;
	}
	printf("Crypto: icp_sal_userStartMultiProcess(\"SSL\",CPA_FALSE)\n");
	return 0;
}


static CpaStatus
enqueueOp(CpaCySymDpOpData *opData, struct rte_port_crypto_writer *p)
{

	CpaStatus status;

	/*
	 * Assumption is there is no requirement to do load balancing between
	 * acceleration units - that is one acceleration unit is tied to a core.
	 */
	opData->instanceHandle = p->instanceHandle;

	if ((++p->kickFreq) % CRYPTO_BURST_TX == 0) {
		status = cpaCySymDpEnqueueOp(opData, CPA_TRUE);
	} else {
		status = cpaCySymDpEnqueueOp(opData, CPA_FALSE);
	}

	p->qaOutstandingRequests++;

	return status;
}

void
crypto_flush_tx_queue(struct rte_port_crypto_writer *p)
{

	cpaCySymDpPerformOpNow(p->instanceHandle);
}

enum crypto_result
crypto_encrypt(struct rte_mbuf *rte_buff, struct rte_port_crypto_writer *p)
{
	CpaCySymDpOpData *opData =
			rte_pktmbuf_mtod_offset(rte_buff, CpaCySymDpOpData *,
						CRYPTO_OFFSET_TO_OPDATA);

	enum cipher_alg c = p->cipher;
	enum hash_alg h = p->hasher;

	if (unlikely(c >= NUM_CRYPTO || h >= NUM_HMAC))
		return CRYPTO_RESULT_FAIL;

	memset(opData, 0, sizeof(CpaCySymDpOpData));

	opData->srcBuffer = opData->dstBuffer = PACKET_DATA_START_PHYS(rte_buff);
	opData->srcBufferLen = opData->dstBufferLen = rte_buff->data_len;
	opData->sessionCtx = p->encryptSessionHandleTbl[c][h];
	opData->thisPhys = PACKET_DATA_START_PHYS(rte_buff)
			+ CRYPTO_OFFSET_TO_OPDATA;
	opData->pCallbackTag = rte_buff;

	/* if no crypto or hash operations are specified return fail */
	if (NO_CIPHER == c && NO_HASH == h)
		return CRYPTO_RESULT_FAIL;

	if (NO_CIPHER != c) {
		opData->pIv = p->pPacketIV;
		opData->iv = p->packetIVPhy;

		if (CIPHER_AES_CBC_128 == c)
			opData->ivLenInBytes = IV_LENGTH_16_BYTES;
		else
			opData->ivLenInBytes = IV_LENGTH_8_BYTES;

		opData->cryptoStartSrcOffsetInBytes = CRYPTO_START_OFFSET;
		opData->messageLenToCipherInBytes = rte_buff->data_len
				- CRYPTO_START_OFFSET;
		/*
		 * Work around for padding, message length has to be a multiple of
		 * block size.
		 */
		opData->messageLenToCipherInBytes -= opData->messageLenToCipherInBytes
				% CIPHER_BLOCK_DEFAULT_SIZE;
	}

	if (NO_HASH != h) {

		opData->hashStartSrcOffsetInBytes = HASH_START_OFFSET;
		opData->messageLenToHashInBytes = rte_buff->data_len
				- HASH_START_OFFSET;
		/*
		 * Work around for padding, message length has to be a multiple of block
		 * size.
		 */
		opData->messageLenToHashInBytes -= opData->messageLenToHashInBytes
				% HASH_BLOCK_DEFAULT_SIZE;

		/*
		 * Assumption: Ok ignore the passed digest pointer and place HMAC at end
		 * of packet.
		 */
		opData->digestResult = rte_buff->buf_physaddr + rte_buff->data_len;
	}

	if (CPA_STATUS_SUCCESS != enqueueOp(opData, p)) {
		/*
		 * Failed to place a packet on the hardware queue.
		 * Most likely because the QA hardware is busy.
		 */
		return CRYPTO_RESULT_FAIL;
	}
	return CRYPTO_RESULT_IN_PROGRESS;
}

enum crypto_result
crypto_decrypt(struct rte_mbuf *rte_buff, struct rte_port_crypto_writer *p)
{

	CpaCySymDpOpData *opData = rte_pktmbuf_mtod_offset(rte_buff, void *,
							   CRYPTO_OFFSET_TO_OPDATA);

	enum cipher_alg c = p->cipher;
	enum hash_alg h = p->hasher;

	if (unlikely(c >= NUM_CRYPTO || h >= NUM_HMAC))
		return CRYPTO_RESULT_FAIL;

	memset(opData, 0, sizeof(CpaCySymDpOpData));

	opData->dstBuffer = opData->srcBuffer = PACKET_DATA_START_PHYS(rte_buff);
	opData->dstBufferLen = opData->srcBufferLen = rte_buff->data_len;
	opData->thisPhys = PACKET_DATA_START_PHYS(rte_buff)
			+ CRYPTO_OFFSET_TO_OPDATA;
	opData->sessionCtx = p->decryptSessionHandleTbl[c][h];
	opData->pCallbackTag = rte_buff;

	/* if no crypto or hmac operations are specified return fail */
	if (NO_CIPHER == c && NO_HASH == h)
		return CRYPTO_RESULT_FAIL;

	if (NO_CIPHER != c) {
		opData->pIv = p->pPacketIV;
		opData->iv = p->packetIVPhy;

		if (CIPHER_AES_CBC_128 == c)
			opData->ivLenInBytes = IV_LENGTH_16_BYTES;
		else
			opData->ivLenInBytes = IV_LENGTH_8_BYTES;

		opData->cryptoStartSrcOffsetInBytes = CRYPTO_START_OFFSET;
		opData->messageLenToCipherInBytes = rte_buff->data_len
				- CRYPTO_START_OFFSET;

		/*
		 * Work around for padding, message length has to be a multiple of block
		 * size.
		 */
		opData->messageLenToCipherInBytes -= opData->messageLenToCipherInBytes
				% CIPHER_BLOCK_DEFAULT_SIZE;
	}
	if (NO_HASH != h) {
		opData->hashStartSrcOffsetInBytes = HASH_START_OFFSET;
		opData->messageLenToHashInBytes = rte_buff->data_len
				- HASH_START_OFFSET;
		/*
		 * Work around for padding, message length has to be a multiple of block
		 * size.
		 */
		opData->messageLenToHashInBytes -= opData->messageLenToHashInBytes
				% HASH_BLOCK_DEFAULT_SIZE;
		opData->digestResult = rte_buff->buf_physaddr + rte_buff->data_len;
	}

	if (CPA_STATUS_SUCCESS != enqueueOp(opData, p)) {
		/*
		 * Failed to place a packet on the hardware queue.
		 * Most likely because the QA hardware is busy.
		 */
		return CRYPTO_RESULT_FAIL;
	}
	return CRYPTO_RESULT_IN_PROGRESS;
}



/*
 * Port CRYPTO Reader
 */
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
	port = rte_zmalloc_socket("PORT", sizeof(*port),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (port == NULL) {
		RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
		return NULL;
	}

	/* Initialization */
	port->socket_id = conf->socket_id;
	port->lcore_id = conf->lcore_id;
	port->port_id = conf->port_id;
	port->ec_dc = conf->ec_dc;

	/* Allocate software ring for response messages. */
	port->callbackQueue.head = 0;
	port->callbackQueue.tail = 0;
	port->callbackQueue.numEntries = 0;
	port->kickFreq = 0;
	port->qaOutstandingRequests = 0;
	port->numResponseAttempts = 0;

	/*** deleted many codes, as this is only a reader rather than writer ***/

	/* Initialise and reserve lcore memzone for virt2phys translation */

	/*
	 * Obtain the instance handle that is mapped to the current lcore.
	 * This can fail if an instance is not mapped to a bank which has been
	 * affinitized to the current lcore.
	 */

	/*
	 * Set the address translation callback for virtual to physcial address
	 * mapping. This will be called by the QAT driver during initialisation only.
	 */

	crypto_readers[port->lcore_id] = port;

	return port;
}

static int
rte_port_crypto_reader_rx(void *port, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	struct rte_port_crypto_reader *p =
		(struct rte_port_crypto_reader *) port;

	//uint16_t pkt_cnt = 0;

	/*mainly induced from 'crypto_get_next_response()'*/
	void *entry = NULL;

	if (p->callbackQ.numEntries) {
		entry = p->callbackQ.qaCallbackRing[p->callbackQ.tail];
		p->callbackQ.tail++;
		p->callbackQ.numEntries--;
	}

	/* If there are no outstanding requests no need to poll, return entry */
	if (p->qaOutstandingRequests == 0)
		return 0;

	if (p->callbackQ.numEntries < CRYPTO_QUEUED_RESP_POLL_THRESHOLD
			&& p->numResponseAttempts++ % GET_NEXT_RESPONSE_FREQ == 0) {
		/*
		 * Only poll the hardware when there is less than
		 * CRYPTO_QUEUED_RESP_POLL_THRESHOLD elements in the software queue
		 */
		icp_sal_CyPollDpInstance(p->instanceHandle,
				CRYPTO_MAX_RESPONSE_QUOTA);
	}

	*pkts = (struct rte_mbuf *) entry;
	//RTE_PORT_CRYPTO_READER_STATS_PKTS_IN_ADD(p, pkt_cnt);
	n_pkts = 0;

	return 1;
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
static void *
rte_port_crypto_writer_create(void *params, int socket_id)
{
	struct rte_port_crypto_writer_params *conf =
			(struct rte_port_crypto_writer_params *) params;
	struct rte_port_crypto_writer *port;

	/* Check input parameters */
	if ((conf == NULL) ||
		(conf->crypto_burst_sz == 0) ||
		(conf->crypto_burst_sz > RTE_PORT_IN_BURST_SIZE_MAX) ||
		(!rte_is_power_of_2(conf->crypto_burst_sz))) {
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
	port->port_id = conf->port_id;
	port->ec_dc = conf->ec_dc;
	port->crypto_burst_sz = conf->crypto_burst_sz;
	port->crypto_buf_count = 0;
	port->bsz_mask = 1LLU << (conf->crypto_burst_sz - 1);

	port->cipher = conf->cipher;
	port->hasher = conf->hasher;

	/* Allocate software ring for response messages. */
	p->callbackQueue.head = 0;
	p->callbackQueue.tail = 0;
	p->callbackQueue.numEntries = 0;
	p->kickFreq = 0;
	p->qaOutstandingRequests = 0;
	p->numResponseAttempts = 0;

	/* Initialise and reserve lcore memzone for virt2phys translation */
	snprintf(memzone_name,
			RTE_MEMZONE_NAMESIZE,
			"lcore_%u",
			p->lcore_id);

	p->lcoreMemzone.memzone = rte_memzone_reserve(
			memzone_name,
			LCORE_MEMZONE_SIZE,
			p->socket_id,
			0);

	if (NULL == p->lcoreMemzone.memzone) {
		printf("Crypto: Error allocating memzone on lcore %u\n", p->lcore_id);
		return -1;
	}
	p->lcoreMemzone.next_free_address = p->lcoreMemzone.memzone->addr;

	p->pPacketIV = alloc_memzone_region(IV_LENGTH_16_BYTES, p);

	if (NULL == p->pPacketIV ) {
		printf("Crypto: Failed to allocate memory for Initialization Vector\n");
		return -1;
	}

	memcpy(p->pPacketIV, &g_crypto_hash_keys.iv,
			IV_LENGTH_16_BYTES);

	p->packetIVPhy = qa_v2p(p->pPacketIV);
	if (0 == p->packetIVPhy) {
		printf("Crypto: Invalid physical address for Initialization Vector\n");
		return -1;
	}

	/*
	 * Obtain the instance handle that is mapped to the current lcore.
	 * This can fail if an instance is not mapped to a bank which has been
	 * affinitized to the current lcore.
	 */
	status = get_crypto_instance_on_core(&(p->instanceHandle), p->lcore_id);

	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: get_crypto_instance_on_core failed with status: %"PRId32"\n",
				status);
		return -1;
	}

	status = cpaCySymDpRegCbFunc(p->instanceHandle,
			(CpaCySymDpCbFunc) qa_crypto_callback);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: cpaCySymDpRegCbFunc failed with status: %"PRId32"\n", status);
		return -1;
	}

	/*
	 * Set the address translation callback for virtual to physcial address
	 * mapping. This will be called by the QAT driver during initialisation only.
	 */
	status = cpaCySetAddressTranslation(p->instanceHandle,
			(CpaVirtualToPhysical) qa_v2p);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: cpaCySetAddressTranslation failed with status: %"PRId32"\n",
				status);
		return -1;
	}

	status = initSessionDataTables(p);
	if (CPA_STATUS_SUCCESS != status) {
		printf("Crypto: Failed to allocate all session tables.");
		return NULL;
	}

	crypto_writers[port->lcore_id] = port;

	return port;
}

static inline void
process_burst(struct rte_port_crypto_writer *p)
{
//	uint32_t nb_process;
//	enum crypto_result ret;
	uint32_t i;

	if(p->ec_dc){
		for(i = 0; i < p->crypto_buf_count; i++)
			crypto_encrypt(p->crypto_buf[i], p);
	}
	else{
		for(i = 0; i < p->crypto_buf_count; i++)
			crypto_decrypt(p->crypto_buf[i], p);
	}


/*	RTE_PORT_CRYPTO_WRITER_STATS_PKTS_DROP_ADD(p, p->crypto_buf_count - nb_send);
	for ( ; nb_send < p->crypto_buf_count; nb_send++)
		rte_pktmbuf_free(p->crypto_buf[nb_send]);
*/
	p->crypto_buf_count = 0;
}

static int
rte_port_crypto_writer_tx(void *port, struct rte_mbuf *pkt)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;

	p->crypto_buf[p->crypto_buf_count++] = pkt;
	RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(p, 1);
	if (p->crypto_buf_count >= p->crypto_burst_sz)
		process_burst(p);

	return 0;
}

static int
rte_port_crypto_writer_tx_bulk(void *port,
		struct rte_mbuf **pkts,
		uint64_t pkts_mask)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;
	uint64_t bsz_mask = p->bsz_mask;
	uint32_t crypto_buf_count = p->crypto_buf_count;
	uint64_t expr = (pkts_mask & (pkts_mask + 1)) |
			((pkts_mask & bsz_mask) ^ bsz_mask);

	if (expr == 0) {
		uint64_t n_pkts = __builtin_popcountll(pkts_mask);
//		uint32_t n_pkts_ok;
		enum crypto_result ret;
		if (crypto_buf_count)
			process_burst(p);

/*		RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(p, n_pkts);
		ret = crypto_encrypt(p->crypto_buf, p->cipher, p->hasher);
*/
/*		RTE_PORT_CRYPTO_WRITER_STATS_PKTS_DROP_ADD(p, n_pkts - n_pkts_ok);
		for ( ; n_pkts_ok < n_pkts; n_pkts_ok++) {
			struct rte_mbuf *pkt = pkts[n_pkts_ok];

			rte_pktmbuf_free(pkt);
		}
*/	} else {
		for ( ; pkts_mask; ) {
			uint32_t pkt_index = __builtin_ctzll(pkts_mask);
			uint64_t pkt_mask = 1LLU << pkt_index;
			struct rte_mbuf *pkt = pkts[pkt_index];

			p->crypto_buf[crypto_buf_count++] = pkt;
			RTE_PORT_CRYPTO_WRITER_STATS_PKTS_IN_ADD(p, 1);
			pkts_mask &= ~pkt_mask;
		}

		p->crypto_buf_count = crypto_buf_count;
		if (crypto_buf_count >= p->crypto_burst_sz)
			process_burst(p);
	}

	return 0;
}

static int
rte_port_crypto_writer_flush(void *port)
{
	struct rte_port_crypto_writer *p =
		(struct rte_port_crypto_writer *) port;

	if (p->tx_buf_count > 0)
		process_burst(p);

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
	.f_tx_bulk = rte_port_crypto_writer_tx_bulk,
	.f_flush = rte_port_crypto_writer_flush,
	.f_stats = rte_port_crypto_writer_stats_read,
};
