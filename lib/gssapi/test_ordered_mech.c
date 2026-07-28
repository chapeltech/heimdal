/*
 * Test mechanism used to verify ordered provider fallback and pinning.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi.h>

static unsigned char test_oid_bytes[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xa9, 0x4a, 0x1a, 0x01
};
static gss_OID_desc test_oid = {
    sizeof(test_oid_bytes), test_oid_bytes
};

static void
trace_call(const char *operation, int continuation)
{
    const char *path = getenv("ORDERED_PROVIDER_TRACE");
    FILE *fp;

    if (path == NULL)
	return;
    fp = fopen(path, "a");
    if (fp == NULL)
	abort();
#ifdef PROVIDER_DECLINES
    fprintf(fp, "decline %s %s\n", operation,
	    continuation ? "continuation" : "initial");
#else
    fprintf(fp, "accept %s %s\n", operation,
	    continuation ? "continuation" : "initial");
#endif
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
    int continuation = *context_handle != GSS_C_NO_CONTEXT;

    trace_call("init", continuation);
    *minor_status = 0;
    if (actual_mech)
	*actual_mech = &test_oid;
    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = GSS_C_INDEFINITE;

#ifdef PROVIDER_DECLINES
    if (getenv("PROVIDER_DIRTY_DECLINE") != NULL) {
	*context_handle = malloc(1);
	output_token->value = strdup("dirty");
	if (*context_handle == GSS_C_NO_CONTEXT ||
	    output_token->value == NULL)
	    return GSS_S_FAILURE;
	output_token->length = 5;
	return GSS_S_BAD_MECH;
    }
    return GSS_S_NO_CRED;
#else
    if (!continuation) {
	static char init_token[] = "init";
	gss_buffer_desc inner = { sizeof(init_token) - 1, init_token };

	*context_handle = malloc(1);
	if (*context_handle == GSS_C_NO_CONTEXT)
	    return GSS_S_FAILURE;
	if (gss_encapsulate_token(&inner, mech_type, output_token) !=
	    GSS_S_COMPLETE)
	    return GSS_S_FAILURE;
	return GSS_S_CONTINUE_NEEDED;
    }
    if (input_token == GSS_C_NO_BUFFER ||
	input_token->length != 6 ||
	memcmp(input_token->value, "accept", 6) != 0)
	return GSS_S_DEFECTIVE_TOKEN;
    return GSS_S_COMPLETE;
#endif
}

OM_uint32 GSSAPI_CALLCONV
gss_accept_sec_context(OM_uint32 *minor_status,
		       gss_ctx_id_t *context_handle,
		       gss_const_cred_id_t verifier_cred_handle,
		       const gss_buffer_t input_token,
		       const gss_channel_bindings_t input_chan_bindings,
		       gss_name_t *src_name,
		       gss_OID *mech_type,
		       gss_buffer_t output_token,
		       OM_uint32 *ret_flags,
		       OM_uint32 *time_rec,
		       gss_cred_id_t *delegated_cred_handle)
{
    int continuation = *context_handle != GSS_C_NO_CONTEXT;

    trace_call("accept", continuation);
    *minor_status = 0;
    if (src_name)
	*src_name = GSS_C_NO_NAME;
    if (mech_type)
	*mech_type = &test_oid;
    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = GSS_C_INDEFINITE;
    if (delegated_cred_handle)
	*delegated_cred_handle = GSS_C_NO_CREDENTIAL;

#ifdef PROVIDER_DECLINES
    if (getenv("PROVIDER_DIRTY_DECLINE") != NULL) {
	*context_handle = malloc(1);
	output_token->value = strdup("dirty");
	if (*context_handle == GSS_C_NO_CONTEXT ||
	    output_token->value == NULL)
	    return GSS_S_FAILURE;
	output_token->length = 5;
	return GSS_S_BAD_MECH;
    }
    return GSS_S_NO_CRED;
#else
    if (!continuation) {
	*context_handle = malloc(1);
	if (*context_handle == GSS_C_NO_CONTEXT)
	    return GSS_S_FAILURE;
	output_token->value = strdup("accept");
	if (output_token->value == NULL)
	    return GSS_S_FAILURE;
	output_token->length = 6;
	return GSS_S_CONTINUE_NEEDED;
    }
    if (input_token == GSS_C_NO_BUFFER || input_token->length != 0)
	return GSS_S_DEFECTIVE_TOKEN;
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

#ifndef PROVIDER_DECLINES
OM_uint32 GSSAPI_CALLCONV
gss_export_sec_context(OM_uint32 *minor_status,
		       gss_ctx_id_t *context_handle,
		       gss_buffer_t interprocess_token)
{
    *minor_status = 0;
    interprocess_token->value = malloc(1);
    if (interprocess_token->value == NULL)
	return GSS_S_FAILURE;
    *(unsigned char *)interprocess_token->value = 0x5a;
    interprocess_token->length = 1;
    free(*context_handle);
    *context_handle = GSS_C_NO_CONTEXT;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_import_sec_context(OM_uint32 *minor_status,
		       const gss_buffer_t interprocess_token,
		       gss_ctx_id_t *context_handle)
{
    *minor_status = 0;
    if (interprocess_token->length != 1 ||
	*(unsigned char *)interprocess_token->value != 0x5a)
	return GSS_S_DEFECTIVE_TOKEN;
    *context_handle = malloc(1);
    return *context_handle == GSS_C_NO_CONTEXT ?
	GSS_S_FAILURE : GSS_S_COMPLETE;
}
#endif
