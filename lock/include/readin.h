#ifndef READIN_H
#define READIN_H

#include "pcsc_common.h"

SCARDCONTEXT pcsc_init(void);

int pcsc_list_readers(SCARDCONTEXT hContext, char *buffer, DWORD *bufLen);

SCARDHANDLE pcsc_connect_card(SCARDCONTEXT hContext, const char *readerName,
                              DWORD *outActiveProtocol);

void pcsc_disconnect_card(SCARDHANDLE hCard);

void pcsc_cleanup(SCARDCONTEXT hContext);

int pcsc_wait_for_card(SCARDCONTEXT hContext, const char *readerName,
                       DWORD timeoutMs);

#endif /* READIN_H */
