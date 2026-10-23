#include <krb5.h>

#ifdef __krb5_asn1_h__
#error <krb5.h> must not include <krb5_asn1.h>
#endif

#include <krb5_asn1.h>

int
main(void)
{
    KDC_REQ req = { 0 };

    (void)req;
    return 0;
}
