/* PKINIT-related certificate OIDs used by hx509. */

#include "hx_locl.h"

#define HX509_OID(name, ...)                                      \
    static unsigned name##_components[] = { __VA_ARGS__ };        \
    const heim_oid name = {                                       \
        sizeof(name##_components) / sizeof(name##_components[0]), \
        name##_components                                         \
    }

HX509_OID(_hx509_oid_id_pkekuoid, 1, 3, 6, 1, 5, 2, 3, 4);
HX509_OID(_hx509_oid_id_pkkdcekuoid, 1, 3, 6, 1, 5, 2, 3, 5);
HX509_OID(_hx509_oid_id_pkinit_san, 1, 3, 6, 1, 5, 2, 2);
HX509_OID(_hx509_oid_id_pkinit_ms_eku, 1, 3, 6, 1, 4, 1, 311, 20, 2, 2);
HX509_OID(_hx509_oid_id_pkinit_ms_san, 1, 3, 6, 1, 4, 1, 311, 20, 2, 3);
HX509_OID(_hx509_oid_id_heim_eku_pkinit_certlife_is_max_life,
          1, 2, 752, 43, 16, 3);

#undef HX509_OID
