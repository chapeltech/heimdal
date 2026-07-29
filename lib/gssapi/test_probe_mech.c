/*
 * Test mechanisms used to verify delayed SPNEGO probing.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <gssapi/gssapi.h>

#if defined(PROBE_MECH_FIRST)
#define PROBE_MECH_LABEL "first"
#define PROBE_MECH_OID_LAST 2
#elif defined(PROBE_MECH_SECOND)
#define PROBE_MECH_LABEL "second"
#define PROBE_MECH_OID_LAST 3
#else
#error "probe mechanism role is not defined"
#endif

static unsigned char test_oid_bytes[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xa9, 0x4a, 0x1a, PROBE_MECH_OID_LAST
};
static gss_OID_desc test_oid = {
    sizeof(test_oid_bytes), test_oid_bytes
};

static void
trace_call(OM_uint32 req_flags)
{
    const char *path = getenv("PROBEONLY_TRACE");
    FILE *fp;

    if (path == NULL)
	return;
    fp = fopen(path, "a");
    if (fp == NULL)
	abort();
    fprintf(fp, "%s %s\n", PROBE_MECH_LABEL,
	    (req_flags & GSS_C_PROBEONLY) ? "probe" : "normal");
    fclose(fp);
}

OM_uint32 GSSAPI_CALLCONV
gss_init_sec_context(OM_uint32 *minor_status,
		     gss_const_cred_id_t claimant_cred_handle,
		     gss_ctx_id_t *context_handle,
		     gss_const_name_t target_name,
		     const gss_OID mech_type,
		     OM_uint32 req_flags,
		     OM_uint32 time_req,
		     const gss_channel_bindings_t input_chan_bindings,
		     const gss_buffer_t input_token,
		     gss_OID *actual_mech,
		     gss_buffer_t output_token,
		     OM_uint32 *ret_flags,
		     OM_uint32 *time_rec)
{
    *minor_status = 0;
    output_token->length = 0;
    output_token->value = NULL;
    if (actual_mech)
	*actual_mech = &test_oid;
    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = GSS_C_INDEFINITE;

    trace_call(req_flags);

#ifdef PROBE_MECH_FIRST
    {
	static char value[] = "optimistic";
	gss_buffer_desc inner = { sizeof(value) - 1, value };
	OM_uint32 major;

	if (req_flags & GSS_C_PROBEONLY)
	    return GSS_S_FAILURE;
	*context_handle = malloc(1);
	if (*context_handle == GSS_C_NO_CONTEXT)
	    return GSS_S_FAILURE;
	major = gss_encapsulate_token(&inner, mech_type, output_token);
	if (major != GSS_S_COMPLETE) {
	    free(*context_handle);
	    *context_handle = GSS_C_NO_CONTEXT;
	    return major;
	}
	return GSS_S_CONTINUE_NEEDED;
    }
#else
    if ((req_flags & GSS_C_PROBEONLY) == 0)
	return GSS_S_FAILURE;
    return GSS_S_COMPLETE;
#endif
}

OM_uint32 GSSAPI_CALLCONV
gss_delete_sec_context(OM_uint32 *minor_status,
		       gss_ctx_id_t *context_handle,
		       gss_buffer_t output_token)
{
    *minor_status = 0;
    free(*context_handle);
    *context_handle = GSS_C_NO_CONTEXT;
    if (output_token != GSS_C_NO_BUFFER) {
	output_token->length = 0;
	output_token->value = NULL;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_import_name(OM_uint32 *minor_status,
		const gss_buffer_t input_name_buffer,
		const gss_OID input_name_type,
		gss_name_t *output_name)
{
    *minor_status = 0;
    *output_name = malloc(1);
    return *output_name == GSS_C_NO_NAME ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_release_name(OM_uint32 *minor_status, gss_name_t *input_name)
{
    *minor_status = 0;
    free(*input_name);
    *input_name = GSS_C_NO_NAME;
    return GSS_S_COMPLETE;
}
