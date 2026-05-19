/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

#ifdef HEIM_ARCFOUR

static krb5_error_code
ARCFOUR_string_to_key(krb5_context context,
		      krb5_enctype enctype,
		      krb5_data password,
		      krb5_salt salt,
		      krb5_data opaque,
		      krb5_keyblock *key)
{
    krb5_error_code ret;
    uint16_t *s = NULL;
    size_t len = 0, i;
    EVP_MD_CTX *m;

    m = EVP_MD_CTX_create();
    if (m == NULL)
	return krb5_enomem(context);

    if (context->ossl->md4 == NULL) {
	krb5_set_error_message(context, KRB5_PROG_ETYPE_NOSUPP,
			       "ARCFOUR string-to-key not supported");
	ret = KRB5_PROG_ETYPE_NOSUPP;
	goto out;
    }

    if (EVP_DigestInit_ex(m, context->ossl->md4, NULL) != 1) {
	ret = _krb5_set_error_message_openssl(context, KRB5_CRYPTO_INTERNAL,
					      "ARCFOUR string-to-key failed");
	goto out;
    }

    ret = wind_utf8ucs2_length(password.data, &len);
    if (ret) {
	krb5_set_error_message (context, ret,
				N_("Password is not valid UTF-8", ""));
	goto out;
    }

    s = malloc (len * sizeof(s[0]));
    if (len != 0 && s == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }

    ret = wind_utf8ucs2(password.data, s, &len);
    if (ret) {
	krb5_set_error_message (context, ret,
				N_("Password is not valid UTF-8", ""));
	goto out;
    }

    /* LE encoding */
    for (i = 0; i < len; i++) {
	unsigned char p;
	p = (s[i] & 0xff);
	if (EVP_DigestUpdate (m, &p, 1) != 1) {
	    ret = _krb5_set_error_message_openssl(context, KRB5_CRYPTO_INTERNAL,
						  "ARCFOUR string-to-key failed");
	    goto out;
	}
	p = (s[i] >> 8) & 0xff;
	if (EVP_DigestUpdate (m, &p, 1) != 1) {
	    ret = _krb5_set_error_message_openssl(context, KRB5_CRYPTO_INTERNAL,
						  "ARCFOUR string-to-key failed");
	    goto out;
	}
    }

    key->keytype = enctype;
    ret = krb5_data_alloc (&key->keyvalue, 16);
    if (ret) {
	krb5_enomem(context);
	goto out;
    }
    if (EVP_DigestFinal_ex (m, key->keyvalue.data, NULL) != 1) {
	krb5_data_free(&key->keyvalue);
	ret = _krb5_set_error_message_openssl(context, KRB5_CRYPTO_INTERNAL,
					      "ARCFOUR string-to-key failed");
	goto out;
    }

 out:
    EVP_MD_CTX_destroy(m);
    if (s)
	memset (s, 0, len);
    free (s);
    return ret;
}

struct salt_type _krb5_arcfour_salt[] = {
    {
	KRB5_PW_SALT,
	"pw-salt",
	ARCFOUR_string_to_key
    },
    { 0, NULL, NULL }
};

#endif /* HEIM_ARCFOUR */
