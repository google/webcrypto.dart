// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:io';

import 'package:ffigen/ffigen.dart';

void main() {
  final packageRoot = Platform.script.resolve('../');

  generateWebCryptoBindings(packageRoot);
  generateBoringSslBindings(packageRoot);
}

void generateWebCryptoBindings(Uri packageRoot) {
  FfiGenerator(
    output: Output(
      dartFile: packageRoot.resolve(
        'lib/src/boringssl/bindings/generated_bindings.dart',
      ),
      style: const NativeExternalBindings(
        assetId: 'package:webcrypto/webcrypto.dart',
      ),
      sort: true,
      commentType: const CommentType(CommentStyle.any, CommentLength.full),
      preamble: '''
// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ignore_for_file: unused_element
// ignore_for_file: non_constant_identifier_names
''',
    ),
    headers: Headers(entryPoints: [packageRoot.resolve('src/webcrypto.h')]),
    functions: Functions(
      include: Declarations.includeSet({'webcrypto_get_CBB_size'}),
    ),
    structs: const Structs(dependencies: CompoundDependencies.opaque),
    typedefs: const Typedefs(include: Declarations.includeAll),
  ).generate();
}

void generateBoringSslBindings(Uri packageRoot) {
  FfiGenerator(
    output: Output(
      dartFile: packageRoot.resolve(
        'lib/src/third_party/boringssl/generated_bindings.dart',
      ),
      style: const NativeExternalBindings(
        assetId: 'package:webcrypto/webcrypto.dart',
      ),
      sort: true,
      commentType: const CommentType(CommentStyle.any, CommentLength.full),
      preamble: '''
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */
// ignore_for_file: camel_case_types
// ignore_for_file: constant_identifier_names
// ignore_for_file: non_constant_identifier_names
// ignore_for_file: unused_element
// ignore_for_file: unused_field
''',
    ),
    headers: Headers(
      entryPoints: [
        packageRoot.resolve('third_party/boringssl/src/include/openssl/aead.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/aes.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/bn.h'),
        packageRoot.resolve(
          'third_party/boringssl/src/include/openssl/bytestring.h',
        ),
        packageRoot.resolve(
          'third_party/boringssl/src/include/openssl/cipher.h',
        ),
        packageRoot.resolve(
          'third_party/boringssl/src/include/openssl/crypto.h',
        ),
        packageRoot.resolve(
          'third_party/boringssl/src/include/openssl/digest.h',
        ),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/ec.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/ecdh.h'),
        packageRoot.resolve(
          'third_party/boringssl/src/include/openssl/ec_key.h',
        ),
        packageRoot.resolve(
          'third_party/boringssl/src/include/openssl/ecdsa.h',
        ),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/err.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/evp.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/hkdf.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/hmac.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/mem.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/rand.h'),
        packageRoot.resolve('third_party/boringssl/src/include/openssl/rsa.h'),
      ],
      compilerOptions: [
        '-Ithird_party/boringssl/src/include',
        '-DBORINGSSL_PREFIX=webcrypto',
        '-U__PRAGMA_REDEFINE_EXTNAME',
      ],
    ),
    macros: Macros(
      include: Declarations.includeSet({
        'AES_BLOCK_SIZE',
        'EC_PKEY_NO_PUBKEY',
        'EVP_PKEY_EC',
        'EVP_PKEY_RSA',
        'HKDF_R_OUTPUT_TOO_LARGE',
        'NID_secp384r1',
        'NID_secp521r1',
        'NID_X9_62_prime256v1',
        'RSA_PKCS1_OAEP_PADDING',
        'RSA_PKCS1_PADDING',
        'RSA_PKCS1_PSS_PADDING',
      }),
    ),
    enums: Enums(
      include: Declarations.includeSet({'point_conversion_form_t'}),
      style: (decl, suggestedStyle) => EnumStyle.intConstants,
    ),
    unnamedEnums: UnnamedEnums(
      include: Declarations.includeSet({'ERR_LIB_HKDF'}),
    ),
    structs: Structs(
      include: Declarations.includeSet({'cbs_st', 'cbb_st'}),
      dependencies: CompoundDependencies.opaque,
    ),
    typedefs: const Typedefs(include: Declarations.includeAll),
    functions: Functions(
      include: Declarations.includeSet({
        // Source of truth for BoringSSL entry points bound from Dart.
        'webcrypto_BN_bin2bn',
        'webcrypto_BN_bn2bin_padded',
        'webcrypto_BN_free',
        'webcrypto_BN_new',
        'webcrypto_BN_num_bytes',
        'webcrypto_BN_set_word',
        'webcrypto_CBB_cleanup',
        'webcrypto_CBB_data',
        'webcrypto_CBB_flush',
        'webcrypto_CBB_init',
        'webcrypto_CBB_len',
        'webcrypto_CBB_zero',
        'webcrypto_CRYPTO_memcmp',
        'webcrypto_ECDH_compute_key',
        'webcrypto_ECDSA_SIG_free',
        'webcrypto_ECDSA_SIG_get0',
        'webcrypto_ECDSA_SIG_marshal',
        'webcrypto_ECDSA_SIG_new',
        'webcrypto_ECDSA_SIG_parse',
        'webcrypto_EC_GROUP_get0_order',
        'webcrypto_EC_GROUP_get_curve_name',
        'webcrypto_EC_GROUP_get_degree',
        'webcrypto_EC_KEY_check_key',
        'webcrypto_EC_KEY_free',
        'webcrypto_EC_KEY_generate_key',
        'webcrypto_EC_KEY_get0_group',
        'webcrypto_EC_KEY_get0_private_key',
        'webcrypto_EC_KEY_get0_public_key',
        'webcrypto_EC_KEY_get_enc_flags',
        'webcrypto_EC_KEY_new_by_curve_name',
        'webcrypto_EC_KEY_set_enc_flags',
        'webcrypto_EC_KEY_set_private_key',
        'webcrypto_EC_KEY_set_public_key',
        'webcrypto_EC_KEY_set_public_key_affine_coordinates',
        'webcrypto_EC_POINT_free',
        'webcrypto_EC_POINT_get_affine_coordinates_GFp',
        'webcrypto_EC_POINT_new',
        'webcrypto_EC_POINT_oct2point',
        'webcrypto_EC_POINT_point2cbb',
        'webcrypto_ERR_clear_error',
        'webcrypto_ERR_error_string_n',
        'webcrypto_ERR_get_error',
        'webcrypto_ERR_peek_error',
        'webcrypto_EVP_aead_aes_128_gcm',
        'webcrypto_EVP_aead_aes_256_gcm',
        'webcrypto_EVP_AEAD_CTX_free',
        'webcrypto_EVP_AEAD_CTX_new',
        'webcrypto_EVP_AEAD_CTX_open',
        'webcrypto_EVP_AEAD_CTX_seal',
        'webcrypto_EVP_AEAD_max_overhead',
        'webcrypto_EVP_aes_128_cbc',
        'webcrypto_EVP_aes_128_ctr',
        'webcrypto_EVP_aes_256_cbc',
        'webcrypto_EVP_aes_256_ctr',
        'webcrypto_EVP_CIPHER_CTX_free',
        'webcrypto_EVP_CIPHER_CTX_new',
        'webcrypto_EVP_CipherFinal_ex',
        'webcrypto_EVP_CipherInit_ex',
        'webcrypto_EVP_CIPHER_iv_length',
        'webcrypto_EVP_CipherUpdate',
        'webcrypto_EVP_DigestFinal',
        'webcrypto_EVP_DigestInit',
        'webcrypto_EVP_DigestSignFinal',
        'webcrypto_EVP_DigestSignInit',
        'webcrypto_EVP_DigestSignUpdate',
        'webcrypto_EVP_DigestUpdate',
        'webcrypto_EVP_DigestVerifyFinal',
        'webcrypto_EVP_DigestVerifyInit',
        'webcrypto_EVP_DigestVerifyUpdate',
        'webcrypto_EVP_marshal_private_key',
        'webcrypto_EVP_marshal_public_key',
        'webcrypto_EVP_MD_CTX_free',
        'webcrypto_EVP_MD_CTX_new',
        'webcrypto_EVP_MD_CTX_size',
        'webcrypto_EVP_parse_private_key',
        'webcrypto_EVP_parse_public_key',
        'webcrypto_EVP_PKEY_CTX_free',
        'webcrypto_EVP_PKEY_CTX_new',
        'webcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label',
        'webcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md',
        'webcrypto_EVP_PKEY_CTX_set_rsa_oaep_md',
        'webcrypto_EVP_PKEY_CTX_set_rsa_padding',
        'webcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen',
        'webcrypto_EVP_PKEY_decrypt',
        'webcrypto_EVP_PKEY_decrypt_init',
        'webcrypto_EVP_PKEY_encrypt',
        'webcrypto_EVP_PKEY_encrypt_init',
        'webcrypto_EVP_PKEY_free',
        'webcrypto_EVP_PKEY_get1_EC_KEY',
        'webcrypto_EVP_PKEY_get1_RSA',
        'webcrypto_EVP_PKEY_id',
        'webcrypto_EVP_PKEY_new',
        'webcrypto_EVP_PKEY_set1_EC_KEY',
        'webcrypto_EVP_PKEY_set1_RSA',
        'webcrypto_EVP_sha1',
        'webcrypto_EVP_sha256',
        'webcrypto_EVP_sha384',
        'webcrypto_EVP_sha512',
        'webcrypto_HKDF',
        'webcrypto_HMAC_CTX_free',
        'webcrypto_HMAC_CTX_new',
        'webcrypto_HMAC_Final',
        'webcrypto_HMAC_Init_ex',
        'webcrypto_HMAC_size',
        'webcrypto_HMAC_Update',
        'webcrypto_OPENSSL_malloc',
        'webcrypto_PKCS5_PBKDF2_HMAC',
        'webcrypto_RAND_bytes',
        'webcrypto_RSA_check_key',
        'webcrypto_RSA_free',
        'webcrypto_RSA_generate_key_ex',
        'webcrypto_RSA_get0_crt_params',
        'webcrypto_RSA_get0_factors',
        'webcrypto_RSA_get0_key',
        'webcrypto_RSA_new',
        'webcrypto_RSAPublicKey_dup',
        'webcrypto_RSA_set0_crt_params',
        'webcrypto_RSA_set0_factors',
        'webcrypto_RSA_set0_key',
        // These are referenced, just need to be sorted right.
        'webcrypto_OPENSSL_free',
        'webcrypto_OPENSSL_memdup',
        'webcrypto_EVP_MD_size',
        // Not used but maybe they should be:
        'webcrypto_EVP_AEAD_nonce_length',
        'webcrypto_EVP_AEAD_max_tag_len',
        // Not used by nice to have, maybe, or maybe we remove / comment them out
        'webcrypto_EVP_AEAD_key_length',
        'webcrypto_BN_value_one',
        'webcrypto_BN_add',
        'webcrypto_BN_sub',
        'webcrypto_BN_cmp',
        'webcrypto_BN_lshift',
        'webcrypto_EVP_CIPHER_block_size',
        'webcrypto_EC_GROUP_new_by_curve_name',
        'webcrypto_EC_GROUP_free',
        'webcrypto_EVP_PKEY_set_type',
        // Self testing only..
        'webcrypto_BORINGSSL_self_test',
      }),
      rename: (decl) {
        final name = decl.originalName;
        if (name.startsWith('webcrypto_')) {
          return name.substring('webcrypto_'.length);
        }
        return name;
      },
    ),
  ).generate();
}
