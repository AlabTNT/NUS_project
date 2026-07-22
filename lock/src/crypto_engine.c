#include <stdio.h>
#include <string.h>
#include <time.h>
#include "crypto_engine.h"

/* ---- internal helpers ---- */

static LONG apdu_send(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                      const BYTE *cmd, DWORD cmdLen,
                      BYTE *resp, DWORD *respLen)
{
    return SCardTransmit(hCard, pio, cmd, cmdLen, NULL, resp, respLen);
}

static int apdu_ok(const BYTE *resp, DWORD respLen)
{
    return (respLen >= 2
            && resp[respLen - 2] == 0x90
            && resp[respLen - 1] == 0x00);
}

static const char *auth_strerror(auth_result_t rc)
{
    switch (rc) {
    case AUTH_SUCCESS:          return "success";
    case AUTH_FAIL_SIGNATURE:   return "credential signature mismatch";
    case AUTH_FAIL_KEY:         return "key load / authentication failed";
    case AUTH_FAIL_READ:        return "block read failure";
    case AUTH_FAIL_CARD:        return "card communication error";
    case AUTH_FAIL_WRITE:       return "block write failure";
    case AUTH_FAIL_INVALID_BLK: return "invalid block address";
    case AUTH_FAIL_ACCESS:      return "access denied (access bits)";
    case AUTH_FAIL_EXPIRED:     return "credential expired";
    case AUTH_FAIL_MAGIC:       return "not a door-lock card (bad magic)";
    case AUTH_FAIL_FORMAT:      return "invalid credential format";
    case AUTH_FAIL_NOT_IN_LIST: return "credential key not in whitelist";
    default:                    return "unknown error";
    }
}

static void hexdump(const char *label, const BYTE *data, int len)
{
    fprintf(stdout, "  %-12s | ", label);
    for (int i = 0; i < len; i++)
        fprintf(stdout, "%02X ", data[i]);
    fprintf(stdout, "\n");
}

/* ---- hex parsing for whitelist ---- */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_key(const char *line, BYTE key[CRED_KEY_LEN])
{
    int i = 0;
    while (*line == ' ' || *line == '\t') line++;
    for (int b = 0; b < CRED_KEY_LEN; b++) {
        int hi = hex_nibble(line[i]);
        int lo = hex_nibble(line[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        key[b] = (BYTE)((hi << 4) | lo);
        i += 2;
    }
    return 0;
}

static int load_whitelist(const char *path,
                          BYTE keys[MAX_WHITELIST_KEYS][CRED_KEY_LEN],
                          int *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[!] Cannot open whitelist: %s\n", path);
        return -1;
    }

    *count = 0;
    char line[256];
    while (*count < MAX_WHITELIST_KEYS && fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (parse_hex_key(line, keys[*count]) == 0)
            (*count)++;
    }
    fclose(f);

    fprintf(stdout, "[*] Loaded %d authorized key(s) from %s\n", *count, path);
    return 0;
}

static int is_in_whitelist(const BYTE key[CRED_KEY_LEN],
                           const BYTE whitelist[MAX_WHITELIST_KEYS][CRED_KEY_LEN],
                           int count)
{
    for (int i = 0; i < count; i++)
        if (memcmp(key, whitelist[i], CRED_KEY_LEN) == 0)
            return 1;
    return 0;
}

/* ---- date helpers ---- */

static int date4_to_int(const BYTE d[4])
{
    return d[0] * 1000000 + d[1] * 10000 + d[2] * 100 + d[3];
}

static int today_int(void)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    return (tm->tm_year + 1900) * 10000
         + (tm->tm_mon  + 1)    * 100
         + tm->tm_mday;
}

static int check_expiry(const BYTE expiryDate[4])
{
    int expiry = date4_to_int(expiryDate);
    int today  = today_int();

    fprintf(stdout, "  expiry  : %08d  (today %08d)\n", expiry, today);

    if (expiry == 0 || expiry >= 99990000)
        return 1;   /* no expiry set */

    if (expiry < today) {
        fprintf(stdout, "  [*] Credential expired %d day(s) ago\n",
                today - expiry);
        return 0;
    }

    fprintf(stdout, "  [*] Valid for %d more day(s)\n", expiry - today);
    return 1;
}

/* ---- key loading ---- */

int mifare_load_key(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                    const BYTE key[MIFARE_KEY_LEN], BYTE keySlot)
{
    BYTE cmd[] = {
        APDU_CLA, APDU_INS_LOAD_KEY, 0x00, keySlot, MIFARE_KEY_LEN,
        key[0], key[1], key[2], key[3], key[4], key[5]
    };
    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = apdu_send(hCard, pio, cmd, sizeof(cmd), resp, &respLen);

    /* ACR122T / some ACS readers reject pseudo-APDU on T=1; retry with T=0 */
    if (rc != SCARD_S_SUCCESS && pio != SCARD_PCI_T0) {
        respLen = sizeof(resp);
        rc = apdu_send(hCard, SCARD_PCI_T0, cmd, sizeof(cmd), resp, &respLen);
    }

    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "  [*] SCardTransmit error: 0x%08lX\n"
                        "      (driver may not support pseudo-APDU on this protocol)\n",
                (unsigned long)rc);
        return AUTH_FAIL_KEY;
    }
    if (!apdu_ok(resp, respLen)) {
        fprintf(stderr, "  [*] Key load rejected: SW=%02X%02X\n",
                respLen >= 2 ? resp[respLen-2] : 0,
                respLen >= 2 ? resp[respLen-1] : 0);
        return AUTH_FAIL_KEY;
    }
    return AUTH_SUCCESS;
}

/* ---- authentication (establishes Crypto-1 encrypted session) ---- */

int mifare_authenticate(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                        BYTE blockAddr, BYTE keyType, BYTE keySlot)
{
    if (blockAddr >= MF1K_TOTAL_BLOCKS)
        return AUTH_FAIL_INVALID_BLK;

    BYTE cmd[] = {
        APDU_CLA, APDU_INS_AUTH, 0x00, 0x00,
        0x05, 0x01, 0x00,
        blockAddr, keyType, keySlot
    };
    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = apdu_send(hCard, pio, cmd, sizeof(cmd), resp, &respLen);

    /* ACR122T fallback to T=0 */
    if (rc != SCARD_S_SUCCESS && pio != SCARD_PCI_T0) {
        respLen = sizeof(resp);
        rc = apdu_send(hCard, SCARD_PCI_T0, cmd, sizeof(cmd), resp, &respLen);
    }

    if (rc != SCARD_S_SUCCESS) return AUTH_FAIL_KEY;

    if (!apdu_ok(resp, respLen)) {
        if (respLen >= 2 && resp[respLen - 2] == 0x63
            && (resp[respLen - 1] & 0xF0) == 0xC0) {
            fprintf(stderr, "  [*] auth failed, %d retries left\n",
                    resp[respLen - 1] & 0x0F);
        }
        return AUTH_FAIL_KEY;
    }
    return AUTH_SUCCESS;
}

/* ---- block read ---- */

int mifare_read_block(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                      BYTE blockAddr, BYTE out[MF1K_BLOCK_SIZE])
{
    if (blockAddr >= MF1K_TOTAL_BLOCKS)
        return AUTH_FAIL_INVALID_BLK;

    BYTE cmd[] = { APDU_CLA, APDU_INS_READ_BIN, 0x00, blockAddr, MF1K_BLOCK_SIZE };
    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = apdu_send(hCard, pio, cmd, sizeof(cmd), resp, &respLen);

    if (rc != SCARD_S_SUCCESS && pio != SCARD_PCI_T0) {
        respLen = sizeof(resp);
        rc = apdu_send(hCard, SCARD_PCI_T0, cmd, sizeof(cmd), resp, &respLen);
    }

    if (rc != SCARD_S_SUCCESS) return AUTH_FAIL_READ;
    if (!apdu_ok(resp, respLen)) return AUTH_FAIL_READ;

    DWORD dataLen = respLen - 2;
    if (dataLen > MF1K_BLOCK_SIZE) dataLen = MF1K_BLOCK_SIZE;
    memcpy(out, resp, dataLen);
    return AUTH_SUCCESS;
}

/* ---- block write ---- */

int mifare_write_block(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                       BYTE blockAddr, const BYTE data[MF1K_BLOCK_SIZE])
{
    if (blockAddr >= MF1K_TOTAL_BLOCKS)
        return AUTH_FAIL_INVALID_BLK;

    BYTE cmd[5 + MF1K_BLOCK_SIZE];
    cmd[0] = APDU_CLA;
    cmd[1] = APDU_INS_UPDATE_BIN;
    cmd[2] = 0x00;
    cmd[3] = blockAddr;
    cmd[4] = MF1K_BLOCK_SIZE;
    memcpy(cmd + 5, data, MF1K_BLOCK_SIZE);

    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = apdu_send(hCard, pio, cmd, sizeof(cmd), resp, &respLen);

    if (rc != SCARD_S_SUCCESS && pio != SCARD_PCI_T0) {
        respLen = sizeof(resp);
        rc = apdu_send(hCard, SCARD_PCI_T0, cmd, sizeof(cmd), resp, &respLen);
    }

    if (rc != SCARD_S_SUCCESS) return AUTH_FAIL_WRITE;
    if (!apdu_ok(resp, respLen)) return AUTH_FAIL_WRITE;
    return AUTH_SUCCESS;
}

/* ---- sector trailer ---- */

int mifare_read_trailer(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                        BYTE blockAddr, BYTE keyA[MIFARE_KEY_LEN],
                        BYTE accessBits[ACCESS_BITS_LEN],
                        BYTE keyB[MIFARE_KEY_LEN])
{
    BYTE data[MF1K_BLOCK_SIZE];
    int rc = mifare_read_block(hCard, pio, blockAddr, data);
    if (rc != AUTH_SUCCESS) return rc;

    memcpy(keyA,       data + TRAILER_KEY_A_OFF,       MIFARE_KEY_LEN);
    memcpy(accessBits, data + TRAILER_ACCESS_BITS_OFF, ACCESS_BITS_LEN);
    memcpy(keyB,       data + TRAILER_KEY_B_OFF,       MIFARE_KEY_LEN);
    return AUTH_SUCCESS;
}

int mifare_write_trailer(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                         BYTE blockAddr,
                         const BYTE keyA[MIFARE_KEY_LEN],
                         const BYTE accessBits[ACCESS_BITS_LEN],
                         const BYTE keyB[MIFARE_KEY_LEN])
{
    BYTE data[MF1K_BLOCK_SIZE];
    memcpy(data + TRAILER_KEY_A_OFF,       keyA,       MIFARE_KEY_LEN);
    memcpy(data + TRAILER_ACCESS_BITS_OFF, accessBits, ACCESS_BITS_LEN);
    memcpy(data + TRAILER_KEY_B_OFF,       keyB,       MIFARE_KEY_LEN);
    return mifare_write_block(hCard, pio, blockAddr, data);
}

/* ---- value-block operations ---- */

int mifare_read_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                      BYTE blockAddr, mf1k_value_block_t *val)
{
    BYTE data[MF1K_BLOCK_SIZE];
    int rc = mifare_read_block(hCard, pio, blockAddr, data);
    if (rc != AUTH_SUCCESS) return rc;
    memcpy(val, data, sizeof(mf1k_value_block_t));
    return AUTH_SUCCESS;
}

int mifare_inc_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                     BYTE blockAddr, DWORD amount)
{
    if (blockAddr >= MF1K_TOTAL_BLOCKS)
        return AUTH_FAIL_INVALID_BLK;

    BYTE cmd[] = {
        APDU_CLA, APDU_INS_VALUE_OP, 0x00, blockAddr,
        0x05,
        0x01, 0x00, 0x00, 0x00,
        (BYTE)(amount        & 0xFF),
        (BYTE)((amount >>  8) & 0xFF),
        (BYTE)((amount >> 16) & 0xFF),
        (BYTE)((amount >> 24) & 0xFF)
    };
    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = apdu_send(hCard, pio, cmd, sizeof(cmd), resp, &respLen);
    if (rc != SCARD_S_SUCCESS) return AUTH_FAIL_WRITE;
    if (!apdu_ok(resp, respLen)) return AUTH_FAIL_WRITE;
    return AUTH_SUCCESS;
}

int mifare_dec_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                     BYTE blockAddr, DWORD amount)
{
    if (blockAddr >= MF1K_TOTAL_BLOCKS)
        return AUTH_FAIL_INVALID_BLK;

    BYTE cmd[] = {
        APDU_CLA, APDU_INS_VALUE_OP, 0x01, blockAddr,
        0x05,
        0x01, 0x00, 0x00, 0x00,
        (BYTE)(amount        & 0xFF),
        (BYTE)((amount >>  8) & 0xFF),
        (BYTE)((amount >> 16) & 0xFF),
        (BYTE)((amount >> 24) & 0xFF)
    };
    BYTE  resp[APDU_RESP_MAX_LEN];
    DWORD respLen = sizeof(resp);

    LONG rc = apdu_send(hCard, pio, cmd, sizeof(cmd), resp, &respLen);
    if (rc != SCARD_S_SUCCESS) return AUTH_FAIL_WRITE;
    if (!apdu_ok(resp, respLen)) return AUTH_FAIL_WRITE;
    return AUTH_SUCCESS;
}

int mifare_restore_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                         BYTE srcBlock, BYTE dstBlock)
{
    mf1k_value_block_t val;
    int rc = mifare_read_value(hCard, pio, srcBlock, &val);
    if (rc != AUTH_SUCCESS) return rc;
    return mifare_write_block(hCard, pio, dstBlock, (const BYTE *)&val);
}

/* ---- sector-level helper ---- */

int mifare_read_sector(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                       BYTE sector, const BYTE keyA[MIFARE_KEY_LEN],
                       BYTE blocks[MF1K_BLOCKS_PER_SECTOR][MF1K_BLOCK_SIZE])
{
    int rc;

    rc = mifare_load_key(hCard, pio, keyA, APDU_LOAD_KEY_SLOT_A);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] load key failed (sector %u)\n", sector);
        return rc;
    }

    BYTE base = (BYTE)(sector * MF1K_BLOCKS_PER_SECTOR);
    rc = mifare_authenticate(hCard, pio, base, MIFARE_KEY_A,
                             APDU_AUTH_KEY_NO);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] auth failed (sector %u)\n", sector);
        return rc;
    }

    for (int i = 0; i < MF1K_BLOCKS_PER_SECTOR; i++) {
        BYTE addr = (BYTE)(base + i);
        rc = mifare_read_block(hCard, pio, addr, blocks[i]);
        if (rc != AUTH_SUCCESS) {
            fprintf(stderr, "[!] read block %u failed\n", addr);
            return rc;
        }
    }
    return AUTH_SUCCESS;
}

/* ================================================================
 *  Door-Lock Credential Verification  (enhanced)
 * ================================================================
 *
 *  @param keyA          6-byte custom Key A; NULL = use default all-FF
 *  @param whitelistPath path to authorized keys file; NULL = skip
 *
 *  1) Load Key A (custom or default), authenticate Sector 1
 *  2) Read Block 4 → verify magic "LOCK"
 *  3) Read Block 5 → verify credKey against whitelist (or non-blank)
 *  4) Read Block 6 → verify expiry date
 *  5) Return AUTH_SUCCESS / AUTH_FAIL_*
 */

int auth_verify_card(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                     const BYTE *keyA, const char *whitelistPath)
{
    BYTE defaultKey[MIFARE_KEY_LEN] = MF1K_DEFAULT_KEY_A;
    BYTE block[MF1K_BLOCK_SIZE];
    int  rc;

    const BYTE *useKey = keyA ? keyA : defaultKey;

    /* ---- load whitelist (if requested) ---- */
    BYTE whitelist[MAX_WHITELIST_KEYS][CRED_KEY_LEN];
    int  wlCount = 0;
    int  useWhitelist = 0;

    if (whitelistPath) {
        if (load_whitelist(whitelistPath, whitelist, &wlCount) == 0
            && wlCount > 0)
            useWhitelist = 1;
    }

    /* ---- 1. load Key A ---- */
    fprintf(stdout, "[*] Loading Key A (%02X%02X%02X%02X%02X%02X) ...\n",
            useKey[0], useKey[1], useKey[2],
            useKey[3], useKey[4], useKey[5]);
    rc = mifare_load_key(hCard, pio, useKey, APDU_LOAD_KEY_SLOT_A);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }

    /* ---- 2. authenticate Sector 1 ---- */
    BYTE authBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR);
    fprintf(stdout, "[*] Authenticating sector %u (block %u) ...\n",
            CRED_SECTOR, authBlock);
    rc = mifare_authenticate(hCard, pio, authBlock, MIFARE_KEY_A,
                             APDU_AUTH_KEY_NO);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s — wrong Key A or not a MIFARE Classic card\n",
                auth_strerror(rc));
        return rc;
    }
    fprintf(stdout, "[+] Crypto-1 session established\n");

    /* ---- 3. read & verify credential header ---- */
    BYTE hdrBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_HDR);
    fprintf(stdout, "[*] Reading credential header (block %u) ...\n", hdrBlock);
    rc = mifare_read_block(hCard, pio, hdrBlock, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }
    hexdump("raw header", block, MF1K_BLOCK_SIZE);

    cred_header_t *hdr = (cred_header_t *)block;
    if (memcmp(hdr->magic, CRED_MAGIC, CRED_MAGIC_LEN) != 0) {
        fprintf(stderr, "[!] bad magic: expected '%.4s', got '%.4s'\n",
                CRED_MAGIC, hdr->magic);
        return AUTH_FAIL_MAGIC;
    }
    fprintf(stdout, "[+] Magic '%.4s' verified\n", CRED_MAGIC);
    fprintf(stdout, "[+] Card serial : %02X %02X %02X %02X\n",
            hdr->cardSerial[0], hdr->cardSerial[1],
            hdr->cardSerial[2], hdr->cardSerial[3]);
    fprintf(stdout, "[+] Access level: %u\n", hdr->accessLevel[0]);

    /* ---- 4. read & verify credential key ---- */
    BYTE keyBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_KEY);
    fprintf(stdout, "[*] Reading credential key (block %u) ...\n", keyBlock);
    rc = mifare_read_block(hCard, pio, keyBlock, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }
    hexdump("cred key", block, MF1K_BLOCK_SIZE);

    if (useWhitelist) {
        if (!is_in_whitelist(block, whitelist, wlCount)) {
            fprintf(stderr, "[!] credential key NOT in whitelist\n");
            return AUTH_FAIL_NOT_IN_LIST;
        }
        fprintf(stdout, "[+] Credential key found in whitelist (%d keys)\n",
                wlCount);
    } else {
        int allFF = 1;
        for (int i = 0; i < CRED_KEY_LEN; i++)
            if (block[i] != 0xFF) { allFF = 0; break; }
        if (allFF) {
            fprintf(stderr, "[!] credential key is blank (all FF)\n");
            return AUTH_FAIL_FORMAT;
        }
        fprintf(stdout, "[+] Credential key non-blank (whitelist mode off)\n");
    }

    /* ---- 5. read metadata & check expiry ---- */
    BYTE metaBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_META);
    fprintf(stdout, "[*] Reading metadata (block %u) ...\n", metaBlock);
    rc = mifare_read_block(hCard, pio, metaBlock, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }
    hexdump("metadata", block, MF1K_BLOCK_SIZE);

    if (!check_expiry(block + 4)) {
        fprintf(stderr, "[!] %s\n", auth_strerror(AUTH_FAIL_EXPIRED));
        return AUTH_FAIL_EXPIRED;
    }

    /* ---- 6. verdict ---- */
    fprintf(stdout, "\n[+] Card credential verification PASSED\n\n");
    return AUTH_SUCCESS;
}
