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

 #ifndef __INCLUDE_RTE_PORT_CRYPTO_H__
 #define __INCLUDE_RTE_PORT_CRYPTO_H__

 #include <stdint.h>

//#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include "rte_port.h"


/* Pass Labels/Values to crypto units *//*
enum cipher_alg {
	NO_CIPHER,
	CIPHER_DES,
	CIPHER_DES_CBC,
	CIPHER_DES3,
	CIPHER_DES3_CBC,
	CIPHER_AES,
	CIPHER_AES_CBC_128,
	CIPHER_KASUMI_F8,
	NUM_CRYPTO,
};

enum hash_alg {
	NO_HASH,
	HASH_MD5,
	HASH_SHA1,
	HASH_SHA1_96,
	HASH_SHA224,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
	HASH_AES_XCBC,
	HASH_AES_XCBC_96,
	HASH_KASUMI_F9,
	NUM_HMAC,
};*/

/* Return value from crypto_{encrypt/decrypt} */
//enum crypto_result {
	/* Packet was successfully put into crypto queue */
//	CRYPTO_RESULT_IN_PROGRESS,
	/* Cryptography has failed in some way */
//	CRYPTO_RESULT_FAIL,
//};



/** crypto_reader port parameters */
struct rte_port_crypto_reader_params {

   /*  */
   uint8_t dev_id;
   uint16_t qp_id;

   uint16_t burst_sz;

   /** encrypto or decrypto flag */
//   uint8_t ec_dc;
};

/** crypto_reader port operations */
extern struct rte_port_in_ops rte_port_crypto_reader_ops;



/** crypto_writer port parameters */
struct rte_port_crypto_writer_params {
   /* */
   uint8_t dev_id;
   /**   */
   uint16_t qp_id;

   unsigned digest_length;

   struct rte_mempool *op_pool;
   struct rte_cryptodev_sym_session *session;

   uint8_t do_cipher;
   uint8_t do_hash;
   uint8_t hash_verify;
   enum rte_crypto_cipher_algorithm cipher_algo;
   enum rte_crypto_auth_algorithm auth_algo;
   enum rte_crypto_op_type op_type;

   uint32_t burst_sz;
};

/** crypto_writer port operations */
extern struct rte_port_out_ops rte_port_crypto_writer_ops;

#endif /* CRYPTO_H_ */
