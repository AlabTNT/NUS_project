#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "pcsc_common.h"
#include "readin.h"
#include "crypto_engine.h"
#include "hardware_ctrl.h"

static SCARDCONTEXT            g_hContext   = 0;
static SCARDHANDLE             g_hCard      = 0;
static const SCARD_IO_REQUEST *g_pioSendPci = NULL;

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
        if (strstr(p, "ACR122") || strstr(p, "ACR12"))
            return p;
        p += strlen(p) + 1;
    }
    return (*readerList) ? readerList : NULL;
}

static void show_card_uid(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio)
{
    BYTE uid[10];
    DWORD uidLen = sizeof(uid);
    int rc = mifare_get_uid(hCard, pio, uid, &uidLen);
    if (rc != AUTH_SUCCESS) {
        fprintf(stdout, "[*] UID: (could not read PICC UID)\n");
        return;
    }

    fprintf(stdout, "[*] UID :");
    for (DWORD i = 0; i < uidLen; i++)
        fprintf(stdout, " %02X", uid[i]);
    fprintf(stdout, "\n");
}

int main(int argc, char **argv)
{
    char        readerList[2048] = {0};
    DWORD       readerLen        = sizeof(readerList);
    const char *targetReader     = NULL;
    const char *keyfile          = DEFAULT_KEYFILE;
    BYTE        customKeyA[MIFARE_KEY_LEN];
    BYTE       *pKeyA            = NULL;
    int         haveCustomKey    = 0;

    /* ---- parse arguments ---- */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--keyfile") && i + 1 < argc) {
            keyfile = argv[++i];
        } else if (!strcmp(argv[i], "--keya") && i + 1 < argc) {
            const char *hex = argv[++i];
            if (strlen(hex) != MIFARE_KEY_LEN * 2) {
                fprintf(stderr, "[!] --keya requires exactly %d hex chars\n",
                        MIFARE_KEY_LEN * 2);
                return 1;
            }
            for (int j = 0; j < MIFARE_KEY_LEN; j++) {
                char hi = (char)toupper(hex[j * 2]);
                char lo = (char)toupper(hex[j * 2 + 1]);
                if (!isxdigit(hi) || !isxdigit(lo)) {
                    fprintf(stderr, "[!] invalid hex in --keya\n");
                    return 1;
                }
                customKeyA[j] = (BYTE)(
                    ((hi >= 'A' ? hi - 'A' + 10 : hi - '0') << 4) |
                     (lo >= 'A' ? lo - 'A' + 10 : lo - '0'));
            }
            haveCustomKey = 1;
            pKeyA = customKeyA;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            fprintf(stdout,
                "Usage: %s [--keyfile PATH] [--keya HEX]\n\n"
                "  --keyfile PATH   whitelist (default: " DEFAULT_KEYFILE ")\n"
                "  --keya HEX       custom 6-byte Key A (12 hex chars)\n\n"
                "Examples:\n"
                "  %s --keyfile keys.txt\n"
                "  %s --keya AABBCCDDEEFF\n\n",
                argv[0], argv[0], argv[0]);
            return 0;
        } else {
            fprintf(stderr, "[!] Unknown option: %s  (use --help)\n", argv[i]);
            return 1;
        }
    }

    install_signal_handler();

    fprintf(stdout,
            "========================================\n"
            "  Smart Card Door Lock System v2.0\n"
            "  Crypto-1 Encrypted Authentication\n"
            "========================================\n\n");

    fprintf(stdout, "  Whitelist   : %s (required)\n", keyfile);
    if (haveCustomKey)
        fprintf(stdout, "  Key A       : %02X%02X%02X%02X%02X%02X (custom)\n",
                customKeyA[0], customKeyA[1], customKeyA[2],
                customKeyA[3], customKeyA[4], customKeyA[5]);
    else
        fprintf(stdout, "  Key A       : FFFFFFFFFFFF (default)\n");
    fprintf(stdout, "\n");

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
        int authResult = auth_verify_card(g_hCard, g_pioSendPci,
                                          pKeyA, keyfile);

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
#ifdef _WIN32
    fprintf(stdout, "\nPress any key to exit...");
    getchar();
#endif
    return 1;
}
