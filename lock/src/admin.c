#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "pcsc_common.h"
#include "readin.h"
#include "crypto_engine.h"

static SCARD_IO_REQUEST g_ioT0 = { SCARD_PROTOCOL_T0, 0 };
static SCARD_IO_REQUEST g_ioT1 = { SCARD_PROTOCOL_T1, 0 };

static const BYTE DEFAULT_KEY_A[MIFARE_KEY_LEN] = MF1K_DEFAULT_KEY_A;
static const BYTE SAFE_ACCESS[ACCESS_BITS_LEN]  = {0xFF, 0x07, 0x80, 0x69};

static BYTE g_defaultKeyB[MIFARE_KEY_LEN] = MF1K_DEFAULT_KEY_B;

static const char *select_reader(const char *readerList)
{
    const char *p = readerList;
    while (*p) {
        if (strstr(p, "ACR122")) return p;
        p += strlen(p) + 1;
    }
    return readerList;
}

static void random_bytes(BYTE *buf, int len)
{
    for (int i = 0; i < len; i++)
        buf[i] = (BYTE)(rand() & 0xFF);
}

static void pack_bcd4(BYTE out[4], int val)
{
    out[3] = (BYTE)(val % 100);               val /= 100;
    out[2] = (BYTE)(val % 100);               val /= 100;
    out[1] = (BYTE)(val % 100);               val /= 100;
    out[0] = (BYTE)(val % 100);
}

static void read_uid(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                     BYTE uid[4])
{
    BYTE buf[MF1K_BLOCK_SIZE];
    if (mifare_read_block(hCard, pio, MF1K_BLOCK_MFR, buf) == AUTH_SUCCESS) {
        memcpy(uid, buf, 4);
    } else {
        memset(uid, 0, 4);
    }
}

static int write_credential(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                            BYTE level, int issueDate, int expiryDate)
{
    BYTE block[MF1K_BLOCK_SIZE];
    BYTE uid[4];
    int rc;

    read_uid(hCard, pio, uid);

    /* ---- Block 4: credential header ---- */
    memset(block, 0, MF1K_BLOCK_SIZE);
    memcpy(block, CRED_MAGIC, CRED_MAGIC_LEN);
    memcpy(block + CRED_MAGIC_LEN, uid, 4);
    block[CRED_MAGIC_LEN + 4] = level;
    block[CRED_MAGIC_LEN + 5] = 0x00;

    BYTE hdrAddr = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_HDR);
    rc = mifare_write_block(hCard, pio, hdrAddr, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] Failed to write header block\n");
        return rc;
    }
    fprintf(stdout, "[+] Wrote credential header  (block %u)\n", hdrAddr);

    /* ---- Block 5: credential key ---- */
    memset(block, 0, MF1K_BLOCK_SIZE);
    random_bytes(block, 8);

    BYTE keyAddr = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_KEY);
    rc = mifare_write_block(hCard, pio, keyAddr, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] Failed to write credential key block\n");
        return rc;
    }
    fprintf(stdout, "[+] Wrote credential key      (block %u)\n", keyAddr);

    /* ---- Block 6: metadata ---- */
    memset(block, 0, MF1K_BLOCK_SIZE);
    pack_bcd4(block, issueDate);
    pack_bcd4(block + 4, expiryDate);

    BYTE metaAddr = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_META);
    rc = mifare_write_block(hCard, pio, metaAddr, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] Failed to write metadata block\n");
        return rc;
    }
    fprintf(stdout, "[+] Wrote metadata             (block %u)\n", metaAddr);

    /************************************************************
     *  WARNING: writing the sector trailer is irreversible.
     *  If access bits or keys are wrong, this sector is bricked.
     *  For safety we skip this step unless --format-trailer is
     *  explicitly passed via the command line.
     ************************************************************/

    return AUTH_SUCCESS;
}

static int format_sector_trailer(SCARDHANDLE hCard,
                                 const SCARD_IO_REQUEST *pio,
                                 const BYTE *keyA)
{
    BYTE trailerAddr = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR
                               + MF1K_SECTOR_TRAILER);
    return mifare_write_trailer(hCard, pio, trailerAddr,
                                keyA, SAFE_ACCESS, g_defaultKeyB);
}

static int verify_credential(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio)
{
    BYTE block[MF1K_BLOCK_SIZE];
    int rc;

    BYTE hdrAddr = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_HDR);
    rc = mifare_read_block(hCard, pio, hdrAddr, block);
    if (rc != AUTH_SUCCESS) return rc;
    if (memcmp(block, CRED_MAGIC, CRED_MAGIC_LEN) != 0) {
        fprintf(stderr, "[!] Verification failed: bad magic in block %u\n", hdrAddr);
        return AUTH_FAIL_MAGIC;
    }
    fprintf(stdout, "[+] Credential verified  (magic OK, block %u)\n", hdrAddr);
    return AUTH_SUCCESS;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--level N] [--expiry YYYYMMDD] [--keya HEX] [--format-trailer]\n"
        "\n"
        "  Programs a MIFARE Classic 1K card with Sector-1 door-lock credentials.\n"
        "  The card must be authenticated with the correct Key A on Sector 1.\n"
        "\n"
        "  --level N          access level 0-255 (default 1)\n"
        "  --expiry YYYYMMDD  expiry date      (default 29991231 = no expiry)\n"
        "  --keya HEX         custom 6-byte Key A as 12 hex chars\n"
        "                     (default: FFFFFFFFFFFF)\n"
        "  --format-trailer   write sector trailer with safe access bits\n"
        "                     WARNING: use custom --keya unless card is default\n"
        "\n"
        "  Example:\n"
        "    %s --keya A1B2C3D4E5F6 --level 3 --expiry 20261231 --format-trailer\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    BYTE  level       = 1;
    int   issueDate   = 0;
    int   expiry      = 29991231;
    int   doTrailer   = 0;
    BYTE  customKeyA[MIFARE_KEY_LEN];
    int   haveCustomKey = 0;

    /* ---- parse args ---- */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--level") && i + 1 < argc) {
            level = (BYTE)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--expiry") && i + 1 < argc) {
            expiry = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--format-trailer")) {
            doTrailer = 1;
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
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "[!] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* derive issue date from system time */
    {
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        issueDate = (tm->tm_year + 1900) * 10000
                  + (tm->tm_mon  + 1)    * 100
                  + tm->tm_mday;
    }

    srand((unsigned)time(NULL));

    fprintf(stdout,
        "========================================\n"
        "  Door Lock Card Programming Tool\n"
        "========================================\n\n");

    fprintf(stdout, "  Access level  : %u\n", level);
    fprintf(stdout, "  Issue date    : %08d\n", issueDate);
    fprintf(stdout, "  Expiry date   : %08d\n", expiry);
    if (haveCustomKey)
        fprintf(stdout, "  Key A         : %02X%02X%02X%02X%02X%02X (custom)\n",
                customKeyA[0], customKeyA[1], customKeyA[2],
                customKeyA[3], customKeyA[4], customKeyA[5]);
    else
        fprintf(stdout, "  Key A         : FFFFFFFFFFFF (default)\n");
    fprintf(stdout, "  Format trailer: %s\n\n", doTrailer ? "YES" : "no");

    /* ---- init PCSC ---- */
    SCARDCONTEXT hContext = pcsc_init();
    if (!hContext) return 1;

    char  readerList[2048] = {0};
    DWORD readerLen        = sizeof(readerList);
    if (pcsc_list_readers(hContext, readerList, &readerLen) != 0) {
        pcsc_cleanup(hContext);
        return 1;
    }

    const char *target = select_reader(readerList);
    if (!target || !*target) {
        fprintf(stderr, "[!] No ACR122U reader found.\n");
        pcsc_cleanup(hContext);
        return 1;
    }
    fprintf(stdout, "[*] Reader: %s\n", target);

    /* ---- wait for card ---- */
    fprintf(stdout, "[*] Place the card on the reader and press Enter...");
    getchar();

    int status = pcsc_wait_for_card(hContext, target, 2000);
    if (status <= 0) {
        fprintf(stderr, "\n[!] No card detected.\n");
        pcsc_cleanup(hContext);
        return 1;
    }
    fprintf(stdout, "\n[+] Card detected.\n\n");

    /* ---- connect ---- */
    DWORD activeProto = 0;
    SCARDHANDLE hCard = pcsc_connect_card(hContext, target, &activeProto);
    if (!hCard) {
        fprintf(stderr, "[!] Cannot connect to card.\n");
        pcsc_cleanup(hContext);
        return 1;
    }

    const SCARD_IO_REQUEST *pio =
        (activeProto == SCARD_PROTOCOL_T1)
            ? (const SCARD_IO_REQUEST *)&g_ioT1
            : (const SCARD_IO_REQUEST *)&g_ioT0;

    const BYTE *useKeyA = haveCustomKey ? customKeyA : DEFAULT_KEY_A;

    /* ---- load Key A & auth Sector 1 ---- */
    int rc = mifare_load_key(hCard, pio, useKeyA, APDU_LOAD_KEY_SLOT_A);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] Key A load failed. Is this a MIFARE Classic card?\n");
        goto done;
    }

    BYTE authBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR);
    rc = mifare_authenticate(hCard, pio, authBlock, MIFARE_KEY_A,
                             APDU_AUTH_KEY_NO);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr,
                "[!] Auth failed on Sector %u; check Key A matches card.\n",
                CRED_SECTOR);
        goto done;
    }
    fprintf(stdout, "[+] Sector %u authenticated.\n\n", CRED_SECTOR);

    /* ---- write credential ---- */
    fprintf(stdout, "---- Writing credential ----\n");
    rc = write_credential(hCard, pio, level, issueDate, expiry);
    if (rc != AUTH_SUCCESS) goto done;

    /* ---- format trailer (optional) ---- */
    if (doTrailer) {
        fprintf(stdout, "\n---- Formatting sector trailer ----\n");
        rc = format_sector_trailer(hCard, pio, useKeyA);
        if (rc != AUTH_SUCCESS) {
            fprintf(stderr, "[!] Failed to write sector trailer.\n");
            goto done;
        }
        fprintf(stdout, "[+] Sector trailer written.\n");
    }

    /* ---- verify ---- */
    fprintf(stdout, "\n---- Verifying ----\n");
    /* re-auth a different block to ensure a fresh encrypted session */
    mifare_authenticate(hCard, pio, (BYTE)(authBlock + 1), MIFARE_KEY_A,
                        APDU_AUTH_KEY_NO);
    rc = verify_credential(hCard, pio);
    if (rc != AUTH_SUCCESS) goto done;

    fprintf(stdout, "\n[+] Card programmed successfully.\n");

done:
    pcsc_disconnect_card(hCard);
    pcsc_cleanup(hContext);
    return (rc == AUTH_SUCCESS) ? 0 : 1;
}
