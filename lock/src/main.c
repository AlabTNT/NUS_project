#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcsc_common.h"
#include "readin.h"
#include "crypto_engine.h"
#include "hardware_ctrl.h"

static SCARDCONTEXT            g_hContext   = 0;
static SCARDHANDLE             g_hCard      = 0;
static const SCARD_IO_REQUEST *g_pioSendPci = NULL;

static SCARD_IO_REQUEST g_ioT0 = { SCARD_PROTOCOL_T0, 0 };
static SCARD_IO_REQUEST g_ioT1 = { SCARD_PROTOCOL_T1, 0 };

static void do_cleanup(void)
{
    fprintf(stdout, "\n[*] Shutting down...\n");
    if (g_hCard) pcsc_disconnect_card(g_hCard);
    hw_cleanup();
    pcsc_cleanup(g_hContext);
}

/* ---- signal / console-event handler ---- */
#ifdef _WIN32
static BOOL WINAPI ctrl_handler(DWORD fdwCtrlType)
{
    (void)fdwCtrlType;
    do_cleanup();
    exit(0);
    return TRUE;
}
static void install_signal_handler(void)
{
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
}
#else
static void sig_handler(int sig)
{
    (void)sig;
    do_cleanup();
    _exit(0);
}
static void install_signal_handler(void)
{
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sig_handler);
}
#endif

static const char *select_reader(const char *readerList)
{
    const char *p = readerList;
    while (*p) {
        if (strstr(p, "ACR122"))
            return p;
        p += strlen(p) + 1;
    }
    return readerList;
}

static void show_card_uid(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio)
{
    BYTE  buf[MF1K_BLOCK_SIZE];
    int   rc = mifare_read_block(hCard, pio, MF1K_BLOCK_MFR, buf);
    if (rc != AUTH_SUCCESS) {
        fprintf(stdout, "[*] UID: (could not read manufacturer block)\n");
        return;
    }
    fprintf(stdout, "[*] UID : %02X %02X %02X %02X  (BCC %02X)\n",
            buf[0], buf[1], buf[2], buf[3], buf[4]);
}

int main(void)
{
    char        readerList[2048] = {0};
    DWORD       readerLen        = sizeof(readerList);
    const char *targetReader     = NULL;

    install_signal_handler();

    fprintf(stdout,
            "========================================\n"
            "  Smart Card Door Lock System v2.0\n"
            "  Crypto-1 Encrypted Authentication\n"
            "========================================\n\n");

    hw_init();

    g_hContext = pcsc_init();
    if (!g_hContext)
        goto fatal;

    if (pcsc_list_readers(g_hContext, readerList, &readerLen) != 0)
        goto fatal;

    targetReader = select_reader(readerList);
    if (!targetReader || !*targetReader) {
        fprintf(stderr, "[!] No suitable reader found.\n");
        goto fatal;
    }
    fprintf(stdout, "[*] Using reader: %s\n\n", targetReader);

    fprintf(stdout, "[*] Entering daemon loop - waiting for card...\n");
    fprintf(stdout, "[*] Press Ctrl+C to exit.\n\n");

    for (;;) {
        /* block until card is detected */
        int status = pcsc_wait_for_card(g_hContext, targetReader, (DWORD)-1);
        if (status < 0) {
            fprintf(stderr, "[!] Status monitor error, retrying...\n");
            SLEEP_MS(RECONNECT_WAIT);
            continue;
        }
        if (status == 0)
            continue;

        /* card detected, connect */
        DWORD activeProto = 0;
        g_hCard = pcsc_connect_card(g_hContext, targetReader, &activeProto);
        if (!g_hCard) {
            SLEEP_MS(POLL_INTERVAL);
            continue;
        }

        g_pioSendPci = (activeProto == SCARD_PROTOCOL_T1)
                           ? (const SCARD_IO_REQUEST *)&g_ioT1
                           : (const SCARD_IO_REQUEST *)&g_ioT0;

        /* display UID (block 0, plaintext) */
        show_card_uid(g_hCard, g_pioSendPci);

        fprintf(stdout,
                "\n---- Crypto-1 Authenticated Session ----\n");

        /* Crypto-1 encrypted credential verification */
        int authResult = auth_verify_card(g_hCard, g_pioSendPci);

        fprintf(stdout,
                "------------------------------------------\n");

        if (authResult == AUTH_SUCCESS) {
            hw_access_granted(g_hCard, g_pioSendPci);
        } else {
            fprintf(stdout, "[!] Auth result: %d\n", authResult);
            hw_access_denied(g_hCard, g_pioSendPci);
        }

        pcsc_disconnect_card(g_hCard);
        g_hCard = 0;

        fprintf(stdout, "[*] Waiting for next card...\n\n");
        SLEEP_MS(CARD_REMOVAL_WAIT);
    }

    do_cleanup();
    return 0;

fatal:
    fprintf(stderr, "[!] Fatal error - system halted.\n");
    do_cleanup();
    return 1;
}
