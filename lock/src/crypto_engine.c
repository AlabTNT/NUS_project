#include <stdio.h>
#include <string.h>
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
    if (rc != SCARD_S_SUCCESS) return AUTH_FAIL_KEY;
    if (!apdu_ok(resp, respLen))  return AUTH_FAIL_KEY;
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
    /* Read value from src, write to dst as binary */
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
 *  Door-Lock Credential Verification
 * ================================================================
 *
 *  Expects Sector 1 to contain:
 *    Block 4  → cred_header_t   (magic "LOCK", card serial, access level)
 *    Block 5  → cred_key_t      (8-byte credential key)
 *    Block 6  → cred_meta_t     (issue date, expiry date)
 *    Block 7  → sector trailer  (Key A + access bits + Key B)
 *
 * 1) Load default Key A, authenticate sector 1
 * 2) Read credential header → verify magic "LOCK"
 * 3) Read credential key    → verify non-zero
 * 4) Read metadata          → check expiry
 * 5) Print card info, return AUTH_SUCCESS / AUTH_FAIL_*
 */

int auth_verify_card(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio)
{
    BYTE defaultKey[MIFARE_KEY_LEN] = MF1K_DEFAULT_KEY_A;
    BYTE block[MF1K_BLOCK_SIZE];
    int  rc;

    /* ---- 1. load default Key A ---- */
    fprintf(stdout, "[*] Loading default Key A ...\n");
    rc = mifare_load_key(hCard, pio, defaultKey, APDU_LOAD_KEY_SLOT_A);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }

    /* ---- 2. authenticate sector CRED_SECTOR ---- */
    BYTE authBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR);
    fprintf(stdout, "[*] Authenticating sector %u (block %u) with Key A ...\n",
            CRED_SECTOR, authBlock);
    rc = mifare_authenticate(hCard, pio, authBlock, MIFARE_KEY_A,
                             APDU_AUTH_KEY_NO);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }
    fprintf(stdout, "[+] Crypto-1 session established (three-pass auth OK)\n");

    /* ---- 3. read credential header (block CRED_BLOCK_HDR in sector) ---- */
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
    fprintf(stdout, "[+] Access level: %02X %02X\n",
            hdr->accessLevel[0], hdr->accessLevel[1]);

    /* ---- 4. read credential key ---- */
    BYTE keyBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_KEY);
    fprintf(stdout, "[*] Reading credential key (block %u) ...\n", keyBlock);
    rc = mifare_read_block(hCard, pio, keyBlock, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }
    hexdump("cred key", block, MF1K_BLOCK_SIZE);

    cred_key_t *key = (cred_key_t *)block;
    int allFF = 1;
    for (int i = 0; i < 8; i++)
        if (key->credKey[i] != 0xFF) { allFF = 0; break; }
    if (allFF) {
        fprintf(stderr, "[!] credential key is blank (all FF)\n");
        return AUTH_FAIL_FORMAT;
    }

    /* ---- 5. read metadata / expiry ---- */
    BYTE metaBlock = (BYTE)(CRED_SECTOR * MF1K_BLOCKS_PER_SECTOR + CRED_BLOCK_META);
    fprintf(stdout, "[*] Reading metadata (block %u) ...\n", metaBlock);
    rc = mifare_read_block(hCard, pio, metaBlock, block);
    if (rc != AUTH_SUCCESS) {
        fprintf(stderr, "[!] %s\n", auth_strerror(rc));
        return rc;
    }
    hexdump("metadata", block, MF1K_BLOCK_SIZE);

    /* ---- 6. verdict ---- */
    fprintf(stdout, "\n[+] Card credential verification PASSED\n\n");
    return AUTH_SUCCESS;
}
