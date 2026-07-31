/* Register the symbolic OIDs from ASN.1 modules owned by libkrb5. */

#include "krb5_locl.h"

void
_krb5_register_asn1_oids(void)
{
#define DEFINE_OID_WITH_NAME(sym) \
    (void)der_register_heim_oid(#sym, &asn1_oid_ ## sym);
#include "krb5_asn1_oids.c"
#include "pkinit_asn1_oids.c"
#include "kx509_asn1_oids.c"
#undef DEFINE_OID_WITH_NAME
}
