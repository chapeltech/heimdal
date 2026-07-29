#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_spnego.h>

static void
check_status(const char *operation, OM_uint32 major, OM_uint32 expected)
{
    if (major != expected) {
	fprintf(stderr, "%s returned %u, expected %u\n",
		operation, major, expected);
	exit(1);
    }
}

static void
check_sanon_probe(void)
{
    static char target[] = "host@test";
    gss_buffer_desc namebuf = { sizeof(target) - 1, target };
    OM_uint32 major, minor;
    gss_name_t name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;

    major = gss_import_name(&minor, &namebuf, GSS_C_NO_OID, &name);
    check_status("gss_import_name for SANON", major, GSS_S_COMPLETE);

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
	&ctx, name, GSS_SANON_X25519_MECHANISM,
	GSS_C_ANON_FLAG | GSS_C_PROBEONLY, GSS_C_INDEFINITE,
	GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, NULL, &token,
	NULL, NULL);
    check_status("available SANON probe", major, GSS_S_COMPLETE);
    if (token.length != 0) {
	fprintf(stderr, "available SANON probe created a token\n");
	exit(1);
    }
    gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
	&ctx, name, GSS_SANON_X25519_MECHANISM,
	GSS_C_PROBEONLY, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
	GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    check_status("unavailable SANON probe", major, GSS_S_BAD_MECH);
    if (ctx != GSS_C_NO_CONTEXT || token.length != 0) {
	fprintf(stderr, "unavailable SANON probe created context state or token\n");
	exit(1);
    }

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
	&ctx, name, GSS_SANON_X25519_MECHANISM,
	GSS_C_ANON_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
	GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    check_status("ordinary SANON initiation", major, GSS_S_CONTINUE_NEEDED);
    if (ctx == GSS_C_NO_CONTEXT || token.length == 0) {
	fprintf(stderr, "ordinary SANON initiation produced no context or token\n");
	exit(1);
    }
    gss_release_buffer(&minor, &token);
    gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
    gss_release_name(&minor, &name);
}

static void
check_spnego_probe_order(void)
{
    static char target[] = "host@test";
    gss_buffer_desc namebuf = { sizeof(target) - 1, target };
    gss_name_t name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    OM_uint32 major, minor;

    major = gss_import_name(&minor, &namebuf, GSS_C_NO_OID, &name);
    check_status("gss_import_name", major, GSS_S_COMPLETE);

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx,
	name, GSS_SPNEGO_MECHANISM, 0, GSS_C_INDEFINITE,
	GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, NULL,
	&token, NULL, NULL);
    check_status("SPNEGO initiation", major, GSS_S_CONTINUE_NEEDED);
    if (token.length == 0) {
	fprintf(stderr, "SPNEGO initiation produced no optimistic token\n");
	exit(1);
    }

    gss_release_buffer(&minor, &token);
    gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
    gss_release_name(&minor, &name);
}

int
main(void)
{
    check_sanon_probe();
    check_spnego_probe_order();
    return 0;
}
