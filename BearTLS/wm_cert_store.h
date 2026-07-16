#ifndef WM_CERT_STORE_H
#define WM_CERT_STORE_H

#include <stddef.h>
#include "bearssl.h"

int wm_cert_store_init(void);
const br_x509_trust_anchor *wm_cert_store_anchors(void);
size_t wm_cert_store_anchor_count(void);

#endif
