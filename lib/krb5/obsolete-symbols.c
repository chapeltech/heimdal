#include "krb5_locl.h"
#include <heimbasepriv.h>

#if defined(PIC) || defined(BUILD_OBSOLETE_SYMBOLS)

static krb5_error_code
compat_not_implemented(void)
{
    return ENOTSUP;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_alloc(krb5_context, krb5_digest *);
KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_digest_free(krb5_digest);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_client_binding(krb5_context, krb5_digest, char **, char **);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_session_key(krb5_context, krb5_digest, krb5_data *);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_tickets(krb5_context, krb5_digest, Ticket **);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_init_request(krb5_context, krb5_digest, krb5_realm, krb5_ccache);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_probe(krb5_context, krb5_realm, krb5_ccache, unsigned *);
KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_digest_rep_get_status(krb5_context, krb5_digest);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_request(krb5_context, krb5_digest, krb5_realm, krb5_ccache);
KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_digest_set_responseData(krb5_context, krb5_digest, const char *);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_server_cb(krb5_context, krb5_digest,
			  const char *, const char *);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_alloc(krb5_context, krb5_ntlm *);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_flags(krb5_context, krb5_ntlm, uint32_t *);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_targetname(krb5_context, krb5_ntlm, char **);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_request(krb5_context, krb5_ntlm, krb5_realm, krb5_ccache,
		       uint32_t, const char *, const char *);
KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_ntlm_rep_get_status(krb5_context, krb5_ntlm);
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_request(krb5_context, krb5_ntlm, krb5_realm, krb5_ccache);
#ifndef _WIN32
KRB5_LIB_FUNCTION void
initialize_heim_error_table(void);
KRB5_LIB_FUNCTION void
initialize_heim_error_table_r(struct et_list **);
#endif

#define DIGEST_ERROR_3(name, type)					\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context, krb5_digest, type);				\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context context, krb5_digest digest, type value)		\
    {									\
	(void)context;							\
	(void)digest;							\
	(void)value;							\
	return compat_not_implemented();					\
    }

#define DIGEST_STRING_GETTER(name)					\
    KRB5_LIB_FUNCTION const char * KRB5_LIB_CALL			\
    name(krb5_context, krb5_digest);					\
    KRB5_LIB_FUNCTION const char * KRB5_LIB_CALL			\
    name(krb5_context context, krb5_digest digest)			\
    {									\
	(void)context;							\
	(void)digest;							\
	return NULL;							\
    }

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_alloc(krb5_context context, krb5_digest *digest)
{
    (void)context;
    if (digest)
	*digest = NULL;
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_digest_free(krb5_digest digest)
{
    (void)digest;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_client_binding(krb5_context context,
			       krb5_digest digest,
			       char **type,
			       char **binding)
{
    (void)context;
    (void)digest;
    if (type)
	*type = NULL;
    if (binding)
	*binding = NULL;
    return compat_not_implemented();
}

DIGEST_STRING_GETTER(krb5_digest_get_identifier)
DIGEST_STRING_GETTER(krb5_digest_get_opaque)
DIGEST_STRING_GETTER(krb5_digest_get_rsp)
DIGEST_STRING_GETTER(krb5_digest_get_server_nonce)

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_session_key(krb5_context context,
			    krb5_digest digest,
			    krb5_data *data)
{
    (void)context;
    (void)digest;
    if (data)
	krb5_data_zero(data);
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_tickets(krb5_context context,
			krb5_digest digest,
			Ticket **tickets)
{
    (void)context;
    (void)digest;
    if (tickets)
	*tickets = NULL;
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_init_request(krb5_context context,
			 krb5_digest digest,
			 krb5_realm realm,
			 krb5_ccache ccache)
{
    (void)context;
    (void)digest;
    (void)realm;
    (void)ccache;
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_probe(krb5_context context,
		  krb5_realm realm,
		  krb5_ccache ccache,
		  unsigned *flags)
{
    (void)context;
    (void)realm;
    (void)ccache;
    if (flags)
	*flags = 0;
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_digest_rep_get_status(krb5_context context, krb5_digest digest)
{
    (void)context;
    (void)digest;
    return FALSE;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_request(krb5_context context,
		    krb5_digest digest,
		    krb5_realm realm,
		    krb5_ccache ccache)
{
    (void)context;
    (void)digest;
    (void)realm;
    (void)ccache;
    return compat_not_implemented();
}

DIGEST_ERROR_3(krb5_digest_set_authentication_user, krb5_principal)
DIGEST_ERROR_3(krb5_digest_set_authid, const char *)
DIGEST_ERROR_3(krb5_digest_set_client_nonce, const char *)
DIGEST_ERROR_3(krb5_digest_set_digest, const char *)
DIGEST_ERROR_3(krb5_digest_set_hostname, const char *)
DIGEST_ERROR_3(krb5_digest_set_identifier, const char *)
DIGEST_ERROR_3(krb5_digest_set_method, const char *)
DIGEST_ERROR_3(krb5_digest_set_nonceCount, const char *)
DIGEST_ERROR_3(krb5_digest_set_opaque, const char *)
DIGEST_ERROR_3(krb5_digest_set_qop, const char *)
DIGEST_ERROR_3(krb5_digest_set_realm, const char *)
KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_digest_set_responseData(krb5_context context,
			     krb5_digest digest,
			     const char *response)
{
    (void)context;
    (void)digest;
    (void)response;
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_server_cb(krb5_context context,
			  krb5_digest digest,
			  const char *type,
			  const char *binding)
{
    (void)context;
    (void)digest;
    (void)type;
    (void)binding;
    return compat_not_implemented();
}

DIGEST_ERROR_3(krb5_digest_set_server_nonce, const char *)
DIGEST_ERROR_3(krb5_digest_set_type, const char *)
DIGEST_ERROR_3(krb5_digest_set_uri, const char *)
DIGEST_ERROR_3(krb5_digest_set_username, const char *)

#define NTLM_ERROR_2(name)						\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context, krb5_ntlm);					\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context context, krb5_ntlm ntlm)				\
    {									\
	(void)context;							\
	(void)ntlm;							\
	return compat_not_implemented();					\
    }

#define NTLM_ERROR_3(name, type)					\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context, krb5_ntlm, type);				\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context context, krb5_ntlm ntlm, type value)		\
    {									\
	(void)context;							\
	(void)ntlm;							\
	(void)value;							\
	return compat_not_implemented();					\
    }

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_alloc(krb5_context context, krb5_ntlm *ntlm)
{
    (void)context;
    if (ntlm)
	*ntlm = NULL;
    return compat_not_implemented();
}

NTLM_ERROR_2(krb5_ntlm_free)

#define NTLM_DATA_GETTER(name)						\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context, krb5_ntlm, krb5_data *);				\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context context, krb5_ntlm ntlm, krb5_data *data)		\
    {									\
	(void)context;							\
	(void)ntlm;							\
	if (data)							\
	    krb5_data_zero(data);					\
	return compat_not_implemented();					\
    }

NTLM_DATA_GETTER(krb5_ntlm_init_get_challenge)

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_flags(krb5_context context,
			 krb5_ntlm ntlm,
			 uint32_t *flags)
{
    (void)context;
    (void)ntlm;
    if (flags)
	*flags = 0;
    return compat_not_implemented();
}

NTLM_DATA_GETTER(krb5_ntlm_init_get_opaque)
NTLM_DATA_GETTER(krb5_ntlm_init_get_targetinfo)

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_targetname(krb5_context context,
			      krb5_ntlm ntlm,
			      char **name)
{
    (void)context;
    (void)ntlm;
    if (name)
	*name = NULL;
    return compat_not_implemented();
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_request(krb5_context context,
		       krb5_ntlm ntlm,
		       krb5_realm realm,
		       krb5_ccache ccache,
		       uint32_t flags,
		       const char *hostname,
		       const char *domainname)
{
    (void)context;
    (void)ntlm;
    (void)realm;
    (void)ccache;
    (void)flags;
    (void)hostname;
    (void)domainname;
    return compat_not_implemented();
}

NTLM_DATA_GETTER(krb5_ntlm_rep_get_sessionkey)

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_ntlm_rep_get_status(krb5_context context, krb5_ntlm ntlm)
{
    (void)context;
    (void)ntlm;
    return FALSE;
}

NTLM_ERROR_3(krb5_ntlm_req_set_flags, uint32_t)

#define NTLM_BLOB_SETTER(name)						\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context, krb5_ntlm, void *, size_t);			\
    KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL			\
    name(krb5_context context, krb5_ntlm ntlm, void *data, size_t len)	\
    {									\
	(void)context;							\
	(void)ntlm;							\
	(void)data;							\
	(void)len;							\
	return compat_not_implemented();					\
    }

NTLM_BLOB_SETTER(krb5_ntlm_req_set_lm)
NTLM_BLOB_SETTER(krb5_ntlm_req_set_ntlm)
NTLM_ERROR_3(krb5_ntlm_req_set_opaque, krb5_data *)
NTLM_BLOB_SETTER(krb5_ntlm_req_set_session)
NTLM_ERROR_3(krb5_ntlm_req_set_targetname, const char *)
NTLM_ERROR_3(krb5_ntlm_req_set_username, const char *)

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_request(krb5_context context,
		  krb5_ntlm ntlm,
		  krb5_realm realm,
		  krb5_ccache ccache)
{
    (void)context;
    (void)ntlm;
    (void)realm;
    (void)ccache;
    return compat_not_implemented();
}

#ifndef _WIN32
KRB5_LIB_FUNCTION void
initialize_heim_error_table(void)
{
    _heim_initialize_heim_error_table_r(&_et_list);
}

KRB5_LIB_FUNCTION void
initialize_heim_error_table_r(struct et_list **list)
{
    _heim_initialize_heim_error_table_r(list);
}
#endif

#endif
