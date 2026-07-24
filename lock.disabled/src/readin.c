#include <stdio.h>
#include <string.h>
#include "readin.h"

SCARDCONTEXT pcsc_init(void)
{
    SCARDCONTEXT hContext = 0;
    LONG rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "[!] SCardEstablishContext failed: 0x%08lX\n",
                (unsigned long)rc);
        return 0;
    }
    fprintf(stdout, "[+] PCSC context established.\n");
    return hContext;
}

int pcsc_list_readers(SCARDCONTEXT hContext, char *buffer, DWORD *bufLen)
{
    LONG rc = SCardListReaders(hContext, NULL, buffer, bufLen);
    if (rc == SCARD_E_NO_READERS_AVAILABLE) {
        fprintf(stderr, "[!] No readers available.\n");
        return -1;
    }
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "[!] SCardListReaders failed: 0x%08lX\n",
                (unsigned long)rc);
        return -1;
    }

    fprintf(stdout, "[+] Detected readers:\n");
    char *p = buffer;
    while (*p) {
        fprintf(stdout, "    - %s\n", p);
        p += strlen(p) + 1;
    }
    return 0;
}

SCARDHANDLE pcsc_connect_card(SCARDCONTEXT hContext, const char *readerName,
                              DWORD *outActiveProtocol)
{
    SCARDHANDLE hCard = 0;
    DWORD dwActiveProtocol = 0;

    LONG rc = SCardConnect(hContext, readerName,
                           SCARD_SHARE_SHARED,
                           PROTOCOL_FLAGS,
                           &hCard, &dwActiveProtocol);
    if (rc != SCARD_S_SUCCESS)
        return 0;

    if (outActiveProtocol)
        *outActiveProtocol = dwActiveProtocol;

    fprintf(stdout, "[+] Card connected (%s)\n", readerName);
    return hCard;
}

void pcsc_disconnect_card(SCARDHANDLE hCard)
{
    if (hCard) {
        SCardDisconnect(hCard, SCARD_LEAVE_CARD);
        fprintf(stdout, "[*] Card disconnected.\n");
    }
}

void pcsc_cleanup(SCARDCONTEXT hContext)
{
    if (hContext) {
        SCardReleaseContext(hContext);
        fprintf(stdout, "[*] PCSC context released.\n");
    }
}

static int wait_for_presence(SCARDCONTEXT hContext, const char *readerName,
                             DWORD timeoutMs, int wantPresent)
{
    SCARD_READERSTATE rgReaderStates[1];

    memset(&rgReaderStates, 0, sizeof(rgReaderStates));
    rgReaderStates[0].szReader       = readerName;
    rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;

    for (;;) {
        LONG rc = SCardGetStatusChange(hContext, timeoutMs, rgReaderStates, 1);
        if (rc == SCARD_E_TIMEOUT)
            return 0;
        if (rc != SCARD_S_SUCCESS)
            return -1;

        DWORD eventState = rgReaderStates[0].dwEventState;
        int isPresent = (eventState & SCARD_STATE_PRESENT) != 0;
        if (isPresent == wantPresent)
            return 1;

        /* Acknowledge this state, then wait for the opposite transition. */
        rgReaderStates[0].dwCurrentState =
            eventState & ~(DWORD)SCARD_STATE_CHANGED;
    }
}

int pcsc_wait_for_card(SCARDCONTEXT hContext, const char *readerName,
                       DWORD timeoutMs)
{
    return wait_for_presence(hContext, readerName, timeoutMs, 1);
}

int pcsc_wait_for_card_removal(SCARDCONTEXT hContext, const char *readerName,
                               DWORD timeoutMs)
{
    return wait_for_presence(hContext, readerName, timeoutMs, 0);
}
