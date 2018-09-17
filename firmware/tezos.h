#ifndef __TEZOS_H__
#define __TEZOS_H__

#include <stdbool.h>
#include "bip32.h"
#include "messages.pb.h"
#include "fsm.h"

typedef struct {
    const uint8_t prefix[5];
    const uint8_t prefixlen;
} tezos_prefix_info;

extern const tezos_prefix_info TEZOS_PREFIX_BYTES[];

int hdnode_get_tezos_address(HDNode *node, char *address, int addrlen);
int hdnode_get_tezos_public_key(HDNode *node, char *public_key, int public_keylen);
bool tezos_sign_tx(HDNode *node, TezosSignTx *msg, TezosSignedTx *resp);

bool signing_protect_button(bool confirm_only);
const tezos_prefix_info *get_tezos_address_prefix(uint8_t tag);
int get_tezos_address_from_contract(TezosContractID *contract, char *address);
int get_tezos_address_by_tag(const uint8_t *implicitaddr, char *address);
void tezos_format_value(uint64_t value, char *formatted_value);
int b58cencode(const uint8_t *src, int srclen, const tezos_prefix_info *prefix, char *out, int outlen);

int tezos_get_operation_bytes(TezosSignTx *msg, uint8_t *out);
int tezos_encode_contract_id(TezosContractID *contract, uint8_t *out);
int tezos_encode_zarith(uint64_t number, uint8_t *out);
int tezos_encode_byte(uint8_t byte, uint8_t *out);
int tezos_encode_bool(bool boolean, uint8_t *out);
int tezos_encode_data_true_prefix(uint8_t *data, int datalen, uint8_t *out);
int tezos_memcpy(uint8_t *out, uint8_t *payload, int srclen);

void layoutRequireConfirmTx(char *destination, uint64_t amount);
void layoutRequireConfirmFee(uint64_t fee, uint64_t amount);
void layoutRequireConfirmOrigination(char *address);
void layoutRequireConfirmOriginationFee(uint64_t balance, uint64_t fee);
void layoutRequireConfirmDelegationBaker(char *baker);
void layoutRequireConfirmSetDelegate(uint64_t fee);
void layoutRequireConfirmRegisterDelegate(char *address, uint64_t fee);

#endif
