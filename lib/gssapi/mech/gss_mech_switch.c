/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_mech_switch.c,v 1.2 2006/02/04 09:40:21 dfr Exp $
 */

#include "mech_locl.h"
#include <heim_threads.h>

#ifndef _PATH_GSS_MECH
#define _PATH_GSS_MECH	"/etc/gss/mech"
#endif

struct _gss_mech_switch_list _gss_mechs = { NULL, NULL } ;
gss_OID_set _gss_mech_oids;
static HEIMDAL_MUTEX _gss_mech_mutex = HEIMDAL_MUTEX_INITIALIZER;

struct _gss_wildcard_mech {
	HEIM_TAILQ_ENTRY(_gss_wildcard_mech) link;
	char *name;
	char *lib;
	size_t order;
};
HEIM_TAILQ_HEAD(_gss_wildcard_mech_list, _gss_wildcard_mech);

static const struct {
	const char *name;
	gssapi_mech_interface (*interface)(void);
} builtin_mechs[] = {
	{ "spnego", __gss_spnego_initialize },
	{ "krb5",   __gss_krb5_initialize },
	{ "sanon",  __gss_sanon_initialize },
	{ NULL, NULL }
};

/*
 * Convert a string containing an OID in 'dot' form
 * (e.g. 1.2.840.113554.1.2.2) to a gss_OID.
 */
static int
_gss_string_to_oid(const char* s, gss_OID *oidp)
{
	int			number_count, i, j;
	size_t			byte_count;
	const char		*p, *q;
	char			*res;
	gss_OID_desc		oid;

	*oidp = GSS_C_NO_OID;

	/*
	 * First figure out how many numbers in the oid, then
	 * calculate the compiled oid size.
	 */
	number_count = 0;
	for (p = s; p; p = q) {
		q = strchr(p, '.');
		if (q) q = q + 1;
		number_count++;
	}

	/*
	 * The first two numbers are in the first byte and each
	 * subsequent number is encoded in a variable byte sequence.
	 */
	if (number_count < 2)
		return (EINVAL);

	/*
	 * We do this in two passes. The first pass, we just figure
	 * out the size. Second time around, we actually encode the
	 * number.
	 */
	res = 0;
	for (i = 0; i < 2; i++) {
		byte_count = 0;
		for (p = s, j = 0; p; p = q, j++) {
			unsigned int number = 0;

			/*
			 * Find the end of this number.
			 */
			q = strchr(p, '.');
			if (q) q = q + 1;

			/*
			 * Read the number of of the string. Don't
			 * bother with anything except base ten.
			 */
			while (*p && *p != '.') {
				number = 10 * number + (*p - '0');
				p++;
			}

			/*
			 * Encode the number. The first two numbers
			 * are packed into the first byte. Subsequent
			 * numbers are encoded in bytes seven bits at
			 * a time with the last byte having the high
			 * bit set.
			 */
			if (j == 0) {
				if (res)
					*res = number * 40;
			} else if (j == 1) {
				if (res) {
					*res += number;
					res++;
				}
				byte_count++;
			} else if (j >= 2) {
				/*
				 * The number is encoded in seven bit chunks.
				 */
				unsigned int t;
				unsigned int bytes;

				bytes = 0;
				for (t = number; t; t >>= 7)
					bytes++;
				if (bytes == 0) bytes = 1;
				while (bytes) {
					if (res) {
						int bit = 7*(bytes-1);

						*res = (number >> bit) & 0x7f;
						if (bytes != 1)
							*res |= 0x80;
						res++;
					}
					byte_count++;
					bytes--;
				}
			}
		}
                if (byte_count == 0)
                    return EINVAL;
		if (!res) {
			res = malloc(byte_count);
			if (!res)
				return (ENOMEM);
			oid.length = byte_count;
			oid.elements = res;
		}
	}

	{
		OM_uint32 minor_status, tmp;

		if (GSS_ERROR(_gss_intern_oid(&minor_status, &oid, oidp))) {
			_gss_free_oid(&tmp, &oid);
			return (minor_status);
		}

		_gss_free_oid(&tmp, &oid);
	}

	return (0);
}

static OM_uint32
unimpl(OM_uint32 *minor_status, ...)
{

	*minor_status = 0;
	return GSS_S_UNAVAILABLE;
}

#define SYM(name)							\
do {									\
	m->gm_mech.gm_ ## name = (_gss_##name##_t *)dlsym(so, "gss_" #name); \
	if (!m->gm_mech.gm_ ## name ||					\
	    m->gm_mech.gm_ ##name == gss_ ## name) {			\
		_gss_mg_log(1, "can't find symbol gss_" #name		\
		    " in %s", lib);					\
		m->gm_mech.gm_ ## name = (_gss_##name##_t *)unimpl;	\
	}								\
} while (0)

#define OPTSYM(name)							\
do {									\
	m->gm_mech.gm_ ## name =  (_gss_##name##_t *)dlsym(so, "gss_" #name); \
	if (m->gm_mech.gm_ ## name == gss_ ## name)			\
		m->gm_mech.gm_ ## name = NULL;				\
} while (0)

/* mech exports gssspi_XXX, internally referred to as gss_XXX */
#define OPTSPISYM(name)							\
do {									\
	m->gm_mech.gm_ ## name =  (_gss_##name##_t *)dlsym(so, "gssspi_" #name); \
} while (0)

/* mech exports gssspi_XXX, internally referred to as gssspi_XXX */
#define OPTSPISPISYM(name)							\
do {									\
	m->gm_mech.gm_ ## name =  (_gss_##name##_t *)dlsym(so, "gssspi_" #name); \
	if (m->gm_mech.gm_ ## name == gssspi_ ## name)			\
		m->gm_mech.gm_ ## name = NULL;				\
} while (0)

#define COMPATSYM(name)							\
do {									\
	m->gm_mech.gm_compat->gmc_ ## name =  (_gss_##name##_t *)dlsym(so, "gss_" #name); \
	if (m->gm_mech.gm_compat->gmc_ ## name == gss_ ## name)		\
		m->gm_mech.gm_compat->gmc_ ## name = NULL;		\
} while (0)

#define COMPATSPISYM(name)						\
do {									\
	m->gm_mech.gm_compat->gmc_ ## name =  (_gss_##name##_t *)dlsym(so, "gssspi_" #name); \
	if (m->gm_mech.gm_compat->gmc_ ## name == gss_ ## name)		\
		m->gm_mech.gm_compat->gmc_ ## name = NULL;		\
} while (0)

/*
 *
 */
static int
add_builtin(gssapi_mech_interface mech, size_t order)
{
    struct _gss_mech_switch *m;
    OM_uint32 minor_status;

    /* not registering any mech is ok */
    if (mech == NULL)
	return 0;

    m = calloc(1, sizeof(*m));
    if (m == NULL)
	return ENOMEM;
    m->gm_so = NULL;
    m->gm_order = order;
    m->gm_mech = *mech;
    _gss_intern_oid(&minor_status, &mech->gm_mech_oid, &m->gm_mech_oid);
    if (minor_status) {
	free(m);
	return minor_status;
    }

    /* pick up the oid sets of names */

    if (m->gm_mech.gm_inquire_names_for_mech)
	(*m->gm_mech.gm_inquire_names_for_mech)(&minor_status,
	    &m->gm_mech.gm_mech_oid, &m->gm_name_types);

    if (m->gm_name_types == NULL &&
	gss_create_empty_oid_set(&minor_status,
                                 &m->gm_name_types) != GSS_S_COMPLETE) {
	free(m);
	return ENOMEM;
    }

    HEIM_TAILQ_INSERT_TAIL(&_gss_mechs, m, gm_link);
    return 0;
}

static void
enable_builtin(const char *name, size_t *order)
{
	size_t i;

	/* name == NULL implies add all mechs */
	for (i=0; builtin_mechs[i].name; i++)
		if (!name || !strcmp(builtin_mechs[i].name, name)) {
			if (add_builtin(builtin_mechs[i].interface(), (*order)++))
			    _gss_mg_log(1, "Out of memory while adding "
					   "builtin %s mechanism to the GSS "
					   "mechanism switch", builtin_mechs[i].name);
		}
}

static int
process_colonline(char *buf, size_t *order)
{
	char *p = buf;
	char *name;

	if (strncmp(":builtin ", buf, strlen(":builtin "))) {
		_gss_mg_log(10, "mech colon line \"%s\" unknown", buf);
		return 0;
	}
	p += strlen(":builtin ");
	while (isspace((unsigned char)*p))
		p++;
	name = strsep(&p, "\n\t ");

	enable_builtin(name, order);
	return 1;
}

static struct _gss_mech_switch *
load_dlopen_mech(const char *name, gss_OID mech_oid, const char *lib,
		 size_t order, int wildcard)
{
#ifdef HAVE_DLOPEN
	OM_uint32	major_status, minor_status;
	_gss_mo_init	*mi;
	struct _gss_mech_switch *m = NULL;
	void		*so = NULL;
	char		*gm_name = NULL;

	_gss_mg_log(10, "loading \"%s\"", name);
	so = dlopen(lib, RTLD_LAZY | RTLD_LOCAL | RTLD_GROUP);
	if (so == NULL) {
		_gss_mg_log(1, "dlopen: %s", dlerror());
		goto bad;
	}

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		goto bad;

	m->gm_so = so;
	m->gm_order = order;
	m->gm_wildcard = wildcard;
	m->gm_mech_oid = mech_oid;
	m->gm_mech.gm_name = gm_name = strdup(name);
	if (gm_name == NULL)
		goto bad;
	m->gm_mech.gm_mech_oid = *mech_oid;
	m->gm_mech.gm_flags = 0;
	m->gm_mech.gm_compat = calloc(1, sizeof(struct gss_mech_compat_desc_struct));
	if (m->gm_mech.gm_compat == NULL)
		goto bad;

	SYM(acquire_cred);
	SYM(release_cred);
	SYM(init_sec_context);
	SYM(accept_sec_context);
	SYM(process_context_token);
	SYM(delete_sec_context);
	SYM(context_time);
	SYM(get_mic);
	SYM(verify_mic);
	SYM(wrap);
	SYM(unwrap);
	OPTSYM(display_status);
	OPTSYM(indicate_mechs);
	SYM(compare_name);
	SYM(display_name);
	SYM(import_name);
	SYM(export_name);
	SYM(release_name);
	OPTSYM(inquire_cred);
	SYM(inquire_context);
	SYM(wrap_size_limit);
	OPTSYM(add_cred);
	OPTSYM(inquire_cred_by_mech);
	SYM(export_sec_context);
	SYM(import_sec_context);
	OPTSYM(inquire_names_for_mech);
	OPTSYM(inquire_mechs_for_name);
	SYM(canonicalize_name);
	SYM(duplicate_name);
	OPTSYM(inquire_cred_by_oid);
	OPTSYM(inquire_sec_context_by_oid);
	OPTSYM(set_sec_context_option);
	OPTSPISYM(set_cred_option);
	OPTSYM(pseudo_random);
	OPTSYM(wrap_iov);
	OPTSYM(unwrap_iov);
	OPTSYM(wrap_iov_length);
	OPTSYM(store_cred);
	OPTSYM(export_cred);
	OPTSYM(import_cred);
	OPTSYM(acquire_cred_from);
	OPTSYM(acquire_cred_impersonate_name);
#if 0
	OPTSYM(iter_creds);
	OPTSYM(destroy_cred);
	OPTSYM(cred_hold);
	OPTSYM(cred_unhold);
	OPTSYM(cred_label_get);
	OPTSYM(cred_label_set);
#endif
	OPTSYM(display_name_ext);
	OPTSYM(inquire_name);
	OPTSYM(get_name_attribute);
	OPTSYM(set_name_attribute);
	OPTSYM(delete_name_attribute);
	OPTSYM(export_name_composite);
	OPTSYM(localname);
	OPTSYM(duplicate_cred);
	OPTSYM(add_cred_from);
	OPTSYM(store_cred_into);
	OPTSPISYM(authorize_localname);
	OPTSPISPISYM(query_mechanism_info);
	OPTSPISPISYM(query_meta_data);
	OPTSPISPISYM(exchange_meta_data);

	mi = (_gss_mo_init *)dlsym(so, "gss_mo_init");
	if (mi != NULL) {
		major_status = mi(&minor_status, mech_oid,
				  &m->gm_mech.gm_mo, &m->gm_mech.gm_mo_num);
		if (GSS_ERROR(major_status))
			goto bad;
	} else {
		/* API-as-SPI compatibility */
		COMPATSYM(inquire_saslname_for_mech);
		COMPATSYM(inquire_mech_for_saslname);
		COMPATSYM(inquire_attrs_for_mech);
		COMPATSPISYM(acquire_cred_with_password);
	}

	/* pick up the oid sets of names */

	if (m->gm_mech.gm_inquire_names_for_mech)
		(*m->gm_mech.gm_inquire_names_for_mech)(&minor_status,
		&m->gm_mech.gm_mech_oid, &m->gm_name_types);

	if (m->gm_name_types == NULL)
		gss_create_empty_oid_set(&minor_status, &m->gm_name_types);

	return m;

bad:
	if (m != NULL) {
		free(m->gm_mech.gm_compat);
		/* do not free OID, it has been interned */
		free(m);
	}
	free(gm_name);
	if (so != NULL)
		dlclose(so);
	return NULL;
#else
	return NULL;
#endif
}

static void
insert_mech_by_order(struct _gss_mech_switch *m)
{
	struct _gss_mech_switch *p;

	HEIM_TAILQ_FOREACH(p, &_gss_mechs, gm_link) {
		if (p->gm_order > m->gm_order) {
			HEIM_TAILQ_INSERT_BEFORE(p, m, gm_link);
			return;
		}
	}
	HEIM_TAILQ_INSERT_TAIL(&_gss_mechs, m, gm_link);
}

static void
process_dlopenline(char *p, size_t order,
		   struct _gss_wildcard_mech_list *wildcards)
{
#ifdef HAVE_DLOPEN
	char *name, *oid, *lib, *kobj;
	struct _gss_mech_switch *m;
	struct _gss_wildcard_mech *w;
	gss_OID mech_oid;

	name = strsep(&p, "\t\n ");
	if (p) while (isspace((unsigned char)*p)) p++;
	oid = strsep(&p, "\t\n ");
	if (p) while (isspace((unsigned char)*p)) p++;
	lib = strsep(&p, "\t\n ");
	if (p) while (isspace((unsigned char)*p)) p++;
	kobj = strsep(&p, "\t\n ");
	if (!name || !oid || !lib || !kobj)
		return;

	if (strcmp(oid, "*") == 0) {
		w = calloc(1, sizeof(*w));
		if (w == NULL)
			return;
		w->name = strdup(name);
		w->lib = strdup(lib);
		w->order = order;
		if (w->name == NULL || w->lib == NULL) {
			free(w->name);
			free(w->lib);
			free(w);
			return;
		}
		HEIM_TAILQ_INSERT_TAIL(wildcards, w, link);
		return;
	}

	if (_gss_string_to_oid(oid, &mech_oid))
		return;

	m = load_dlopen_mech(name, mech_oid, lib, order, 0);
	if (m != NULL)
		HEIM_TAILQ_INSERT_TAIL(&_gss_mechs, m, gm_link);
#endif
}

static int
mech_has_attribute(gssapi_mech_interface m, gss_const_OID attribute)
{
	size_t i;

	for (i = 0; i < m->gm_mo_num; i++) {
		if ((m->gm_mo[i].flags & GSS_MO_MA) &&
		    gss_oid_equal(m->gm_mo[i].option, attribute))
			return 1;
	}
	return 0;
}

static int
concrete_mechanism_p(gssapi_mech_interface m)
{
	if (gss_oid_equal(&m->gm_mech_oid, GSS_SPNEGO_MECHANISM))
		return 0;
	if (mech_has_attribute(m, GSS_C_MA_MECH_NEGO) ||
	    mech_has_attribute(m, GSS_C_MA_MECH_PSEUDO) ||
	    mech_has_attribute(m, GSS_C_MA_MECH_COMPOSITE))
		return 0;
	return 1;
}

static int
loaded_mech_supports_oid(gssapi_mech_interface m, gss_const_OID oid)
{
	gss_OID_set mechs = GSS_C_NO_OID_SET;
	OM_uint32 major, minor;
	int present = 0;

	if (m->gm_indicate_mechs == NULL)
		return 1;
	major = m->gm_indicate_mechs(&minor, &mechs);
	if (major == GSS_S_COMPLETE && mechs != GSS_C_NO_OID_SET)
		gss_test_oid_set_member(&minor, rk_UNCONST(oid), mechs, &present);
	gss_release_oid_set(&minor, &mechs);
	return major == GSS_S_COMPLETE && present;
}

static void
free_loaded_mech(struct _gss_mech_switch *m)
{
	OM_uint32 minor;

	if (m == NULL)
		return;
	gss_release_oid_set(&minor, &m->gm_name_types);
	free(m->gm_mech.gm_compat);
	free(rk_UNCONST(m->gm_mech.gm_name));
#ifdef HAVE_DLOPEN
	if (m->gm_so != NULL)
		dlclose(m->gm_so);
#endif
	free(m);
}

static int
build_public_mech_order(void)
{
	struct _gss_mech_switch *m;
	OM_uint32 major, minor;

	HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
		if (m->gm_wildcard)
			continue;
		major = gss_add_oid_set_member(&minor, &m->gm_mech.gm_mech_oid,
					      &_gss_mech_oids);
		if (GSS_ERROR(major))
			return ENOMEM;
	}
	return 0;
}

static void
expand_wildcards(struct _gss_wildcard_mech_list *wildcards)
{
	struct _gss_wildcard_mech *w;
	size_t i;

	HEIM_TAILQ_FOREACH(w, wildcards, link) {
		for (i = 0; i < _gss_mech_oids->count; i++) {
			gss_OID oid = &_gss_mech_oids->elements[i];
			struct _gss_mech_switch *public_entry;
			struct _gss_mech_switch *m;

			HEIM_TAILQ_FOREACH(public_entry, &_gss_mechs, gm_link) {
				if (!public_entry->gm_wildcard &&
				    gss_oid_equal(&public_entry->gm_mech.gm_mech_oid,
						  oid))
					break;
			}
			if (public_entry == NULL ||
			    !concrete_mechanism_p(&public_entry->gm_mech))
				continue;
			m = load_dlopen_mech(w->name, oid, w->lib, w->order, 1);
			if (m != NULL &&
			    loaded_mech_supports_oid(&m->gm_mech, oid))
				insert_mech_by_order(m);
			else
				free_loaded_mech(m);
		}
	}
}

static void
free_wildcards(struct _gss_wildcard_mech_list *wildcards)
{
	struct _gss_wildcard_mech *w;

	while ((w = HEIM_TAILQ_FIRST(wildcards)) != NULL) {
		HEIM_TAILQ_REMOVE(wildcards, w, link);
		free(w->name);
		free(w->lib);
		free(w);
	}
}

static void
init_mech_switch_list(void *p)
{
    struct _gss_mech_switch_list *mechs = p;

    HEIM_TAILQ_INIT(mechs);
}

/*
 * Load the mechanisms file (/etc/gss/mech).
 */
void
_gss_load_mech(void)
{
	OM_uint32	major_status, minor_status;
	static heim_base_once_t once = HEIM_BASE_ONCE_INIT;
	FILE		*fp;
	char		buf[256];
	const char	*conf = secure_getenv("GSS_MECH_CONFIG");
	int		particular_builtins = 0;
	size_t		order = 0;
	struct _gss_wildcard_mech_list wildcards;

	heim_base_once_f(&once, &_gss_mechs, init_mech_switch_list);
	HEIM_TAILQ_INIT(&wildcards);

	HEIMDAL_MUTEX_lock(&_gss_mech_mutex);

	if (!HEIM_TAILQ_EMPTY(&_gss_mechs)) {
		HEIMDAL_MUTEX_unlock(&_gss_mech_mutex);
		return;
	}

	major_status = gss_create_empty_oid_set(&minor_status,
	    &_gss_mech_oids);
	if (major_status) {
		HEIMDAL_MUTEX_unlock(&_gss_mech_mutex);
		return;
	}

	fp = fopen(conf ? conf : _PATH_GSS_MECH, "r");
	if (!fp)
		goto out;
	rk_cloexec_file(fp);

		while (fgets(buf, sizeof(buf), fp)) {
			switch (buf[0]) {
			case '#':
				break;
			case ':':
				if (process_colonline(buf, &order))
					particular_builtins = 1;
				break;
			default:
				process_dlopenline(buf, order++, &wildcards);
			}
		}
	fclose(fp);

out:
	if (!particular_builtins)
		enable_builtin(NULL, &order);	/* All builtins */

	if (build_public_mech_order() == 0)
		expand_wildcards(&wildcards);
	free_wildcards(&wildcards);

	HEIMDAL_MUTEX_unlock(&_gss_mech_mutex);
}

gssapi_mech_interface
__gss_get_default_mechanism(void)
{
	_gss_load_mech();
	if (_gss_mech_oids == GSS_C_NO_OID_SET ||
	    _gss_mech_oids->count == 0)
		return NULL;
	return __gss_get_mechanism(&_gss_mech_oids->elements[0]);
}

gssapi_mech_interface
__gss_get_mechanism(gss_const_OID mech)
{
	return __gss_get_mechanism_next(mech, NULL);
}

gssapi_mech_interface
__gss_get_mechanism_next(gss_const_OID mech, gssapi_mech_interface previous)
{
	struct _gss_mech_switch *m;
	int found = previous == NULL;

	_gss_load_mech();
	HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
		if (!found) {
			if (&m->gm_mech == previous)
				found = 1;
			continue;
		}
		if (gss_oid_equal(&m->gm_mech.gm_mech_oid, mech))
			return &m->gm_mech;
	}
	return NULL;
}

gss_OID
_gss_mg_support_mechanism(gss_const_OID mech)
{
	struct _gss_mech_switch *m;

	_gss_load_mech();
	HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
		if (gss_oid_equal(&m->gm_mech.gm_mech_oid, mech))
			return m->gm_mech_oid;
	}
	return NULL;
}

enum mech_name_match {
	MATCH_NONE = 0,
	MATCH_COMPLETE,
	MATCH_PARTIAL
};

static enum mech_name_match
match_mech_name(const char *gm_mech_name,
		const char *name,
		size_t namelen)
{
	if (gm_mech_name == NULL)
		return MATCH_NONE;
	else if (strcasecmp(gm_mech_name, name) == 0)
		return MATCH_COMPLETE;
	else if (strncasecmp(gm_mech_name, name, namelen) == 0)
		return MATCH_PARTIAL;
	else
		return MATCH_NONE;
}

/*
 * Return an OID for a built-in or dynamically loaded mechanism. For
 * API compatibility with previous versions, we treat "Kerberos 5"
 * as an alias for "krb5". Unique partial matches are supported.
 */
GSSAPI_LIB_FUNCTION gss_OID GSSAPI_CALLCONV
gss_name_to_oid(const char *name)
{
	struct _gss_mech_switch *m, *partial = NULL;
	gss_OID oid = GSS_C_NO_OID;
	size_t namelen = strlen(name);

	if (isdigit((unsigned char)name[0]) &&
	    _gss_string_to_oid(name, &oid) == 0)
		return oid;

	_gss_load_mech();
	HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
		enum mech_name_match match;

		match = match_mech_name(m->gm_mech.gm_name, name, namelen);
		if (match == MATCH_NONE &&
		    gss_oid_equal(m->gm_mech_oid, GSS_KRB5_MECHANISM))
			match = match_mech_name("Kerberos 5", name, namelen);

		if (match == MATCH_COMPLETE)
			return m->gm_mech_oid;
		else if (match == MATCH_PARTIAL) {
			if (partial)
				return NULL;
			else
				partial = m;
		}
	}

	if (partial)
		return partial->gm_mech_oid;

	return NULL;
}

GSSAPI_LIB_FUNCTION const char * GSSAPI_LIB_CALL
gss_oid_to_name(gss_const_OID oid)
{
	struct _gss_mech_switch *m;

	_gss_load_mech();
	HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
		if (gss_oid_equal(m->gm_mech_oid, oid))
			return m->gm_mech.gm_name;
	}

	return NULL;
}
