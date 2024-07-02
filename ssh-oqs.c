/* $OpenBSD: ssh-oqs.c,v 1.8 2020/02/26 13:40:09 jsg Exp $ */
/*
 * Adapted from ssh-ed25519.c for OQS and hybrid algs.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"

#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"
#include "ssh.h"

#include "oqs/oqs.h"

/* returns the size of an oqs public key */
static size_t oqs_sig_pk_len(int type)
{
  switch (type) {
///// OQS_TEMPLATE_FRAGMENT_RETURN_PK_LEN_START
    case KEY_FALCON_512:
    case KEY_RSA3072_FALCON_512:
    case KEY_ECDSA_NISTP256_FALCON_512:return OQS_SIG_falcon_512_length_public_key;
    case KEY_FALCON_1024:
    case KEY_ECDSA_NISTP521_FALCON_1024:return OQS_SIG_falcon_1024_length_public_key;
    case KEY_DILITHIUM_2:
    case KEY_RSA3072_DILITHIUM_2:
    case KEY_ECDSA_NISTP256_DILITHIUM_2:return OQS_SIG_dilithium_2_length_public_key;
    case KEY_DILITHIUM_3:
    case KEY_ECDSA_NISTP384_DILITHIUM_3:return OQS_SIG_dilithium_3_length_public_key;
    case KEY_DILITHIUM_5:
    case KEY_ECDSA_NISTP521_DILITHIUM_5:return OQS_SIG_dilithium_5_length_public_key;
    case KEY_SPHINCS_SHA2_128F_SIMPLE:
    case KEY_RSA3072_SPHINCS_SHA2_128F_SIMPLE:
    case KEY_ECDSA_NISTP256_SPHINCS_SHA2_128F_SIMPLE:return OQS_SIG_sphincs_sha2_128f_simple_length_public_key;
    case KEY_SPHINCS_SHA2_256F_SIMPLE:
    case KEY_ECDSA_NISTP521_SPHINCS_SHA2_256F_SIMPLE:return OQS_SIG_sphincs_sha2_256f_simple_length_public_key;
///// OQS_TEMPLATE_FRAGMENT_RETURN_PK_LEN_END
  }
  return 0;
}

/* returns the size of an oqs secret key */
static size_t oqs_sig_sk_len(int type)
{
  switch (type) {
///// OQS_TEMPLATE_FRAGMENT_RETURN_SK_LEN_START
    case KEY_FALCON_512:
    case KEY_RSA3072_FALCON_512:
    case KEY_ECDSA_NISTP256_FALCON_512:
      return OQS_SIG_falcon_512_length_secret_key;
    case KEY_FALCON_1024:
    case KEY_ECDSA_NISTP521_FALCON_1024:
      return OQS_SIG_falcon_1024_length_secret_key;
    case KEY_DILITHIUM_2:
    case KEY_RSA3072_DILITHIUM_2:
    case KEY_ECDSA_NISTP256_DILITHIUM_2:
      return OQS_SIG_dilithium_2_length_secret_key;
    case KEY_DILITHIUM_3:
    case KEY_ECDSA_NISTP384_DILITHIUM_3:
      return OQS_SIG_dilithium_3_length_secret_key;
    case KEY_DILITHIUM_5:
    case KEY_ECDSA_NISTP521_DILITHIUM_5:
      return OQS_SIG_dilithium_5_length_secret_key;
    case KEY_SPHINCS_SHA2_128F_SIMPLE:
    case KEY_RSA3072_SPHINCS_SHA2_128F_SIMPLE:
    case KEY_ECDSA_NISTP256_SPHINCS_SHA2_128F_SIMPLE:
      return OQS_SIG_sphincs_sha2_128f_simple_length_secret_key;
    case KEY_SPHINCS_SHA2_256F_SIMPLE:
    case KEY_ECDSA_NISTP521_SPHINCS_SHA2_256F_SIMPLE:
      return OQS_SIG_sphincs_sha2_256f_simple_length_secret_key;
///// OQS_TEMPLATE_FRAGMENT_RETURN_SK_LEN_END
  }
  return 0;
}

static int ssh_generic_size(struct sshkey *k)
{
  return k->oqs_pk_len;
}

static int ssh_generic_alloc(struct sshkey *k)
{
  k->oqs_sk = NULL;
  k->oqs_pk = NULL;
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  return 0;
}

static void ssh_generic_cleanup(struct sshkey *k)
{
  freezero(k->oqs_sk, k->oqs_sk_len);
  k->oqs_sk = NULL;
  freezero(k->oqs_pk, k->oqs_pk_len);
  k->oqs_pk = NULL;
}

static int ssh_generic_equal(const struct sshkey *a, const struct sshkey *b)
{
  if (a->oqs_pk == NULL || b->oqs_pk == NULL) {
    return 0;
  }
  if (a->oqs_pk_len != b->oqs_pk_len) {
    return 0;
  }
  if (memcmp(a->oqs_pk, b->oqs_pk, a->oqs_pk_len) != 0) {
    return 0;
  }
  return 1;
}

static int ssh_generic_serialize_public(const struct sshkey *key,
  struct sshbuf *b, enum sshkey_serialize_rep opts)
{
  int r;
  if (key->oqs_pk == NULL) {
    return SSH_ERR_INVALID_ARGUMENT;
  }
  if ((r = sshbuf_put_string(b, key->oqs_pk, key->oqs_pk_len)) != 0) {
    return r;
  }
  return 0;
}

static int ssh_generic_deserialize_public(const char *ktype, struct sshbuf *b,
  struct sshkey *key)
{
  u_char *pk = NULL;
  size_t len = 0;
  int r;

  if ((r = sshbuf_get_string(b, &pk, &len)) != 0) {
    return r;
  }
  if (len != key->oqs_pk_len) {
    freezero(pk, len);
    return SSH_ERR_INVALID_FORMAT;
  }
  key->oqs_pk = pk;
  return 0;
}

static int ssh_generic_serialize_private(const struct sshkey *key,
  struct sshbuf *b, enum sshkey_serialize_rep opts)
{
  int r;
  if ((r = sshbuf_put_string(b, key->oqs_pk, key->oqs_pk_len)) != 0 ||
      (r = sshbuf_put_string(b, key->oqs_sk, key->oqs_sk_len)) != 0) {
    return r;
  }
  return 0;
}

static int ssh_generic_deserialize_private(const char *ktype, struct sshbuf *b,
  struct sshkey *key)
{
  int r;
  size_t pklen = 0;
  size_t sklen = 0;
  u_char *oqs_pk = NULL;
  u_char *oqs_sk = NULL;
  if ((r = sshbuf_get_string(b, &oqs_pk, &pklen)) != 0 ||
      (r = sshbuf_get_string(b, &oqs_sk, &sklen)) != 0) {
    goto out;
  }
  if (pklen != key->oqs_pk_len || sklen != key->oqs_sk_len) {
    r = SSH_ERR_INVALID_FORMAT;
    goto out;
  }
  key->oqs_pk = oqs_pk;
  key->oqs_sk = oqs_sk;
  oqs_pk = NULL;
  oqs_sk = NULL;
  r = 0;
  out:
    freezero(oqs_pk, pklen);
    freezero(oqs_sk, sklen);
    return r;
}

static int ssh_generic_copy_public(const struct sshkey *from, struct sshkey *to)
{
  if (from->oqs_pk != NULL) {
    if ((to->oqs_pk = malloc(from->oqs_pk_len)) == NULL) {
      return SSH_ERR_ALLOC_FAIL;
    }
    memcpy(to->oqs_pk, from->oqs_pk, from->oqs_pk_len);
  }
  return 0;
}

static int ssh_generic_sign(OQS_SIG *oqs_sig,
                            const char *alg_pretty_name,
                            const struct sshkey *key,
                            u_char **sigp,
                            size_t *lenp,
                            const u_char *data,
                            size_t datalen,
                            u_int compat)
{
  u_char *sig = NULL;
  size_t slen = 0, len;
  int r;
  struct sshbuf *b = NULL;
  struct sshbuf *ssh_algname = NULL;
  char *ssh_algname_str = NULL;

  if (lenp != NULL)
    *lenp = 0;

  if (sigp != NULL)
    *sigp = NULL;

  if (key == NULL || key->oqs_sk == NULL)
    return SSH_ERR_INVALID_ARGUMENT;

  slen = oqs_sig->length_signature;
  if ((sig = malloc(slen)) == NULL)
    return SSH_ERR_ALLOC_FAIL;

  if (OQS_SIG_sign(oqs_sig, sig, &slen, data, datalen, key->oqs_sk) != OQS_SUCCESS) {
    r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
    goto out;
  }

  /* encode signature */
  if ((b = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  if ((ssh_algname = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_putf(ssh_algname, "%s-%s", "ssh", alg_pretty_name)) != 0 ||
      (ssh_algname_str = sshbuf_dup_string(ssh_algname)) == NULL) {
      goto out;
  }

  if ((r = sshbuf_put_cstring(b, ssh_algname_str)) != 0 ||
      (r = sshbuf_put_string(b, sig, slen)) != 0)
    goto out;

  len = sshbuf_len(b);
  if (sigp != NULL) {
    if ((*sigp = malloc(len)) == NULL) {
      r = SSH_ERR_ALLOC_FAIL;
      goto out;
    }
    memcpy(*sigp, sshbuf_ptr(b), len);
  }
  if (lenp != NULL)
    *lenp = len;

  /* success */
  r = 0;

out:
  sshbuf_free(b);
  sshbuf_free(ssh_algname);
  free(ssh_algname_str);
  if (sig != NULL)
    freezero(sig, slen);
  return r;
}

static int ssh_generic_verify(OQS_SIG *oqs_sig,
                              const char *alg_pretty_name,
                              const struct sshkey *key,
                              const u_char *signature,
                              size_t signaturelen,
                              const u_char *data,
                              size_t datalen,
                              u_int compat)
{
  struct sshbuf *b = NULL;
  char *algname = NULL;
  struct sshbuf *algname_expected = NULL;
  char *algname_expected_str = NULL;
  const u_char *sigblob;
  size_t slen;
  int r;

  if (key == NULL ||
      key->oqs_pk == NULL ||
      signature == NULL || signaturelen == 0)
    return SSH_ERR_INVALID_ARGUMENT;

  if ((b = sshbuf_from(signature, signaturelen)) == NULL)
    return SSH_ERR_ALLOC_FAIL;

  if ((r = sshbuf_get_cstring(b, &algname, NULL)) != 0 ||
      (r = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)
    goto out;

  if ((algname_expected = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_putf(algname_expected, "%s-%s", "ssh", alg_pretty_name)) != 0 ||
      (algname_expected_str = sshbuf_dup_string(algname_expected)) == NULL) {
      goto out;
  }

  if (strcmp(algname, algname_expected_str) != 0) {
    r = SSH_ERR_KEY_TYPE_MISMATCH;
    goto out;
  }

  if (sshbuf_len(b) != 0) {
    r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
    goto out;
  }

  if (slen > oqs_sig->length_signature) {
    r = SSH_ERR_INVALID_FORMAT;
    goto out;
  }

  if (OQS_SIG_verify(oqs_sig, data, datalen, sigblob, slen, key->oqs_pk) != OQS_SUCCESS) {
    r = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }
  /* success */
  r = 0;

out:
  sshbuf_free(b);
  sshbuf_free(algname_expected);
  free(algname_expected_str);
  return r;
}

///// OQS_TEMPLATE_FRAGMENT_DEFINE_SIG_FUNCTIONS_START
/*---------------------------------------------------
 * FALCON_512 METHODS
 *---------------------------------------------------
 */
static int ssh_falcon512_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_falcon_512_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_falcon512_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "falcon512", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_falcon512_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "falcon512", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_falcon512_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_falcon512_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_falcon512_sign,
  /* .verify = */ ssh_falcon512_verify,
};

const struct sshkey_impl sshkey_falcon512_impl = {
  /* .name = */ "ssh-falcon512",
  /* .shortname = */ "FALCON512",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_FALCON_512,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_falcon512_funcs,
};
/*---------------------------------------------------
 * FALCON_1024 METHODS
 *---------------------------------------------------
 */
static int ssh_falcon1024_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_falcon_1024_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_falcon1024_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "falcon1024", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_falcon1024_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "falcon1024", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_falcon1024_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_falcon1024_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_falcon1024_sign,
  /* .verify = */ ssh_falcon1024_verify,
};

const struct sshkey_impl sshkey_falcon1024_impl = {
  /* .name = */ "ssh-falcon1024",
  /* .shortname = */ "FALCON1024",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_FALCON_1024,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_falcon1024_funcs,
};
/*---------------------------------------------------
 * DILITHIUM_2 METHODS
 *---------------------------------------------------
 */
static int ssh_dilithium2_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_dilithium_2_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_dilithium2_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "dilithium2", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_dilithium2_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "dilithium2", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_dilithium2_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_dilithium2_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_dilithium2_sign,
  /* .verify = */ ssh_dilithium2_verify,
};

const struct sshkey_impl sshkey_dilithium2_impl = {
  /* .name = */ "ssh-dilithium2",
  /* .shortname = */ "DILITHIUM2",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_DILITHIUM_2,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_dilithium2_funcs,
};
/*---------------------------------------------------
 * DILITHIUM_3 METHODS
 *---------------------------------------------------
 */
static int ssh_dilithium3_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_dilithium_3_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_dilithium3_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "dilithium3", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_dilithium3_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "dilithium3", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_dilithium3_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_dilithium3_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_dilithium3_sign,
  /* .verify = */ ssh_dilithium3_verify,
};

const struct sshkey_impl sshkey_dilithium3_impl = {
  /* .name = */ "ssh-dilithium3",
  /* .shortname = */ "DILITHIUM3",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_DILITHIUM_3,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_dilithium3_funcs,
};
/*---------------------------------------------------
 * DILITHIUM_5 METHODS
 *---------------------------------------------------
 */
static int ssh_dilithium5_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_dilithium_5_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_dilithium5_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "dilithium5", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_dilithium5_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "dilithium5", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_dilithium5_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_dilithium5_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_dilithium5_sign,
  /* .verify = */ ssh_dilithium5_verify,
};

const struct sshkey_impl sshkey_dilithium5_impl = {
  /* .name = */ "ssh-dilithium5",
  /* .shortname = */ "DILITHIUM5",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_DILITHIUM_5,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_dilithium5_funcs,
};
/*---------------------------------------------------
 * SPHINCS_SHA2_128F_SIMPLE METHODS
 *---------------------------------------------------
 */
static int ssh_sphincssha2128fsimple_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_sphincs_sha2_128f_simple_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_sphincssha2128fsimple_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "sphincssha2128fsimple", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_sphincssha2128fsimple_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "sphincssha2128fsimple", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_sphincssha2128fsimple_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_sphincssha2128fsimple_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_sphincssha2128fsimple_sign,
  /* .verify = */ ssh_sphincssha2128fsimple_verify,
};

const struct sshkey_impl sshkey_sphincssha2128fsimple_impl = {
  /* .name = */ "ssh-sphincssha2128fsimple",
  /* .shortname = */ "SPHINCSSHA2128FSIMPLE",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_SPHINCS_SHA2_128F_SIMPLE,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_sphincssha2128fsimple_funcs,
};
/*---------------------------------------------------
 * SPHINCS_SHA2_256F_SIMPLE METHODS
 *---------------------------------------------------
 */
static int ssh_sphincssha2256fsimple_generate(struct sshkey *k, int bits)
{
  k->oqs_pk_len = oqs_sig_pk_len(k->type);
  k->oqs_sk_len = oqs_sig_sk_len(k->type);
  if ((k->oqs_pk = malloc(k->oqs_pk_len)) == NULL ||
      (k->oqs_sk = malloc(k->oqs_sk_len)) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  return OQS_SIG_sphincs_sha2_256f_simple_keypair(k->oqs_pk, k->oqs_sk);
}

int ssh_sphincssha2256fsimple_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     const char *alg,
                     const char *sk_provider,
                     const char *sk_pin,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "sphincssha2256fsimple", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

int ssh_sphincssha2256fsimple_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       const char *alg,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "sphincssha2256fsimple", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}

static const struct sshkey_impl_funcs sshkey_sphincssha2256fsimple_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_sphincssha2256fsimple_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_sphincssha2256fsimple_sign,
  /* .verify = */ ssh_sphincssha2256fsimple_verify,
};

const struct sshkey_impl sshkey_sphincssha2256fsimple_impl = {
  /* .name = */ "ssh-sphincssha2256fsimple",
  /* .shortname = */ "SPHINCSSHA2256FSIMPLE",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_SPHINCS_SHA2_256F_SIMPLE,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_sphincssha2256fsimple_funcs,
};

#ifdef HYBRID_IMPLEMENTATION_EXISTS
// #ifdef WITH_OPENSSL
static const struct sshkey_impl_funcs sshkey_rsa3072_falcon512_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_rsa3072_falcon512_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_rsa3072_falcon512_sign,
  /* .verify = */ ssh_rsa3072_falcon512_verify,
};

const struct sshkey_impl sshkey_rsa3072_falcon512_impl = {
  /* .name = */ "ssh-rsa3072_falcon512",
  /* .shortname = */ "RSA3072_FALCON512",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_FALCON_512,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_rsa3072_falcon512_funcs,
};
static const struct sshkey_impl_funcs sshkey_rsa3072_dilithium2_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_rsa3072_dilithium2_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_rsa3072_dilithium2_sign,
  /* .verify = */ ssh_rsa3072_dilithium2_verify,
};

const struct sshkey_impl sshkey_rsa3072_dilithium2_impl = {
  /* .name = */ "ssh-rsa3072_dilithium2",
  /* .shortname = */ "RSA3072_DILITHIUM2",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_DILITHIUM_2,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_rsa3072_dilithium2_funcs,
};
static const struct sshkey_impl_funcs sshkey_rsa3072_sphincssha2128fsimple_funcs = {
  /* .size = */ ssh_generic_size,
  /* .alloc = */ ssh_generic_alloc,
  /* .cleanup = */ ssh_generic_cleanup,
  /* .equal = */ ssh_generic_equal,
  /* .ssh_serialize_public = */ ssh_generic_serialize_public,
  /* .ssh_deserialize_public = */ ssh_generic_deserialize_public,
  /* .ssh_serialize_private = */ ssh_generic_serialize_private,
  /* .ssh_deserialize_private = */ ssh_generic_deserialize_private,
  /* .generate = */ ssh_rsa3072_sphincssha2128fsimple_generate,
  /* .copy_public = */ ssh_generic_copy_public,
  /* .sign = */ ssh_rsa3072_sphincssha2128fsimple_sign,
  /* .verify = */ ssh_rsa3072_sphincssha2128fsimple_verify,
};

const struct sshkey_impl sshkey_rsa3072_sphincssha2128fsimple_impl = {
  /* .name = */ "ssh-rsa3072_sphincssha2128fsimple",
  /* .shortname = */ "RSA3072_SPHINCSSHA2128FSIMPLE",
  /* .sigalg = */ NULL,
  /* .type = */ KEY_SPHINCS_SHA2_128F_SIMPLE,
  /* .nid = */ 0,
  /* .cert = */ 0,
  /* .sigonly = */ 0,
  /* .keybits = */ 256, // TODO - What should be here?
  /* .funcs = */ &sshkey_rsa3072_sphincssha2128fsimple_funcs,
};
#endif /* WITH_OPENSSL */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_SIG_FUNCTIONS_END
