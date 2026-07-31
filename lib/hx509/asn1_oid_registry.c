/* Register the symbolic OIDs from ASN.1 modules owned by libhx509. */

#include "hx_locl.h"

void
_hx509_register_asn1_oids(void)
{
#define DEFINE_OID_WITH_NAME(sym) \
    (void)der_register_heim_oid(#sym, &asn1_oid_ ## sym);
#include "rfc2459_asn1_oids.c"
#include "rfc4108_asn1_oids.c"
#include "cms_asn1_oids.c"
#include "ocsp_asn1_oids.c"
#include "pkcs8_asn1_oids.c"
#include "pkcs9_asn1_oids.c"
#include "pkcs10_asn1_oids.c"
#include "pkcs12_asn1_oids.c"
#undef DEFINE_OID_WITH_NAME
}
