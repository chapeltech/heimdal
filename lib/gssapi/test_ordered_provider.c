#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <gssapi/gssapi.h>

static unsigned char test_oid_bytes[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xa9, 0x4a, 0x1a, 0x01
};
static gss_OID_desc test_oid = {
    sizeof(test_oid_bytes), test_oid_bytes
};

static void
check_status(const char *operation, OM_uint32 major, OM_uint32 expected)
{
    if (major != expected) {
	fprintf(stderr, "%s returned %u, expected %u\n",
		operation, major, expected);
	exit(1);
    }
}

int
main(void)
{
    OM_uint32 major, minor;
    gss_ctx_id_t initiator = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor = GSS_C_NO_CONTEXT;
    gss_buffer_desc initiator_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc acceptor_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc exported_context = GSS_C_EMPTY_BUFFER;
    gss_OID actual_mech = GSS_C_NO_OID;

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &initiator,
	GSS_C_NO_NAME, GSS_C_NO_OID, 0, GSS_C_INDEFINITE,
	GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, &actual_mech,
	&initiator_token, NULL, NULL);
    check_status("initial gss_init_sec_context", major,
		 getenv("PROVIDER_DIRTY_DECLINE") != NULL ?
		 GSS_S_BAD_MECH : GSS_S_CONTINUE_NEEDED);

    if (getenv("PROVIDER_DIRTY_DECLINE") != NULL) {
	static char value[] = "token";
	gss_buffer_desc inner = { sizeof(value) - 1, value };

	if (initiator != GSS_C_NO_CONTEXT) {
	    fprintf(stderr, "dirty initiator decline returned a context\n");
	    return 1;
	}
	major = gss_encapsulate_token(&inner, &test_oid, &initiator_token);
	check_status("gss_encapsulate_token", major, GSS_S_COMPLETE);
	major = gss_accept_sec_context(&minor, &acceptor,
	    GSS_C_NO_CREDENTIAL, &initiator_token,
	    GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &acceptor_token,
	    NULL, NULL, NULL);
	check_status("dirty gss_accept_sec_context", major, GSS_S_BAD_MECH);
	if (acceptor != GSS_C_NO_CONTEXT) {
	    fprintf(stderr, "dirty acceptor decline returned a context\n");
	    return 1;
	}
	gss_release_buffer(&minor, &initiator_token);
	gss_release_buffer(&minor, &acceptor_token);
	return 0;
    }

    major = gss_export_sec_context(&minor, &initiator, &exported_context);
    check_status("gss_export_sec_context (initiator)", major,
		 GSS_S_COMPLETE);
    major = gss_import_sec_context(&minor, &exported_context, &initiator);
    check_status("gss_import_sec_context (initiator)", major,
		 GSS_S_COMPLETE);
    gss_release_buffer(&minor, &exported_context);

    major = gss_accept_sec_context(&minor, &acceptor, GSS_C_NO_CREDENTIAL,
	&initiator_token, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL,
	&acceptor_token, NULL, NULL, NULL);
    check_status("initial gss_accept_sec_context", major,
		 GSS_S_CONTINUE_NEEDED);
    gss_release_buffer(&minor, &initiator_token);

    major = gss_export_sec_context(&minor, &acceptor, &exported_context);
    check_status("gss_export_sec_context (acceptor)", major,
		 GSS_S_COMPLETE);
    major = gss_import_sec_context(&minor, &exported_context, &acceptor);
    check_status("gss_import_sec_context (acceptor)", major,
		 GSS_S_COMPLETE);
    gss_release_buffer(&minor, &exported_context);

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &initiator,
	GSS_C_NO_NAME, GSS_C_NO_OID, 0, GSS_C_INDEFINITE,
	GSS_C_NO_CHANNEL_BINDINGS, &acceptor_token, &actual_mech,
	&initiator_token, NULL, NULL);
    check_status("continued gss_init_sec_context", major, GSS_S_COMPLETE);
    gss_release_buffer(&minor, &acceptor_token);

    major = gss_accept_sec_context(&minor, &acceptor, GSS_C_NO_CREDENTIAL,
	&initiator_token, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL,
	&acceptor_token, NULL, NULL, NULL);
    check_status("continued gss_accept_sec_context", major, GSS_S_COMPLETE);

    gss_release_buffer(&minor, &initiator_token);
    gss_release_buffer(&minor, &acceptor_token);
    gss_delete_sec_context(&minor, &initiator, GSS_C_NO_BUFFER);
    gss_delete_sec_context(&minor, &acceptor, GSS_C_NO_BUFFER);
    return 0;
}
