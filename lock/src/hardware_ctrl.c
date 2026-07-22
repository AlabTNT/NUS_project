#include <stdio.h>
#include "hardware_ctrl.h"

static int send_led_command(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
                            BYTE ledState, DWORD blinkDuration)
{
    BYTE cmd[] = {
        0xFF, 0x00, 0x40, ledState,
        0x04,
        (BYTE)(blinkDuration        & 0xFF),
        (BYTE)((blinkDuration >>  8) & 0xFF),
        (BYTE)((blinkDuration >> 16) & 0xFF),
        (BYTE)((blinkDuration >> 24) & 0xFF)
    };
    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = SCardTransmit(hCard, pioSendPci, cmd, sizeof(cmd),
                            NULL, resp, &respLen);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "[!] LED command failed: 0x%08lX\n",
                (unsigned long)rc);
        return -1;
    }
    return 0;
}

void hw_init(void)
{
    fprintf(stdout, "[*] Hardware control module initialised.\n");
}

void hw_access_granted(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci)
{
    fprintf(stdout,
            "\n"
            "  ==========================\n"
            "  |   ACCESS GRANTED       |\n"
            "  ==========================\n\n");

    send_led_command(hCard, pioSendPci, 0x08, 500);
    SLEEP_MS(500);
    send_led_command(hCard, pioSendPci, 0x0C, 0);
}

void hw_access_denied(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci)
{
    fprintf(stdout,
            "\n"
            "  ==========================\n"
            "  |   ACCESS DENIED        |\n"
            "  ==========================\n\n");

    for (int i = 0; i < 3; i++) {
        send_led_command(hCard, pioSendPci, 0x04, 200);
        SLEEP_MS(200);
    }
    send_led_command(hCard, pioSendPci, 0x0C, 0);
}

void hw_cleanup(void)
{
    fprintf(stdout, "[*] Hardware control module cleaned up.\n");
}
