#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include "pcsc_common.h"

/*
 * ================================================================
 *  MIFARE Classic 1K  Crypto-1  encrypted session operations
 * ================================================================
 *
 *  Typical call sequence:
 *
 *    1) mifare_load_key()          → load key into reader volatile slot
 *    2) mifare_authenticate()      → three-pass auth (establishes
 *                                     Crypto-1 encrypted session)
 *    3) mifare_read_block()        → read 16 B under encryption
 *       mifare_write_block()       → write 16 B under encryption
 *    4) (session expires on card removal / disconnect)
 */

/* ---- key loading ---- */
int mifare_load_key(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                    const BYTE key[MIFARE_KEY_LEN], BYTE keySlot);

/* ---- authentication (establishes Crypto-1 encrypted session) ---- */
int mifare_authenticate(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                        BYTE blockAddr, BYTE keyType, BYTE keySlot);

/* ---- block I/O ---- */
int mifare_read_block(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                      BYTE blockAddr, BYTE out[MF1K_BLOCK_SIZE]);

int mifare_write_block(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                       BYTE blockAddr, const BYTE data[MF1K_BLOCK_SIZE]);

/* ---- sector trailer ---- */
int mifare_read_trailer(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                        BYTE blockAddr, BYTE keyA[MIFARE_KEY_LEN],
                        BYTE accessBits[ACCESS_BITS_LEN],
                        BYTE keyB[MIFARE_KEY_LEN]);

int mifare_write_trailer(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                         BYTE blockAddr,
                         const BYTE keyA[MIFARE_KEY_LEN],
                         const BYTE accessBits[ACCESS_BITS_LEN],
                         const BYTE keyB[MIFARE_KEY_LEN]);

/* ---- value-block operations ---- */
int mifare_read_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                      BYTE blockAddr, mf1k_value_block_t *val);

int mifare_inc_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                     BYTE blockAddr, DWORD amount);

int mifare_dec_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                     BYTE blockAddr, DWORD amount);

int mifare_restore_value(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                         BYTE srcBlock, BYTE dstBlock);

/* ---- sector-level helpers ---- */
int mifare_read_sector(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pio,
                       BYTE sector, const BYTE keyA[MIFARE_KEY_LEN],
                       BYTE blocks[MF1K_BLOCKS_PER_SECTOR][MF1K_BLOCK_SIZE]);

/* ---- door-lock credential verification ---- */
int auth_verify_card(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci);

#endif /* CRYPTO_ENGINE_H */
