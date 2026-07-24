#ifndef HARDWARE_CTRL_H
#define HARDWARE_CTRL_H

#include "pcsc_common.h"

void hw_init(void);

void hw_access_granted(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci);

void hw_access_denied(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci);

void hw_cleanup(void);

#endif /* HARDWARE_CTRL_H */
