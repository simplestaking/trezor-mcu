#include <stdbool.h>
#include <stdlib.h>
#include "tezos.h"
#include "curves.h"
#include "blake2b.h"
#include "base58.h"
#include "hasher.h"
#include "layout2.h"
#include "gettext.h"
#include "protect.h"
#include "crypto.h"

#define TEZOS_ADDRESS_LEN 37
#define CONTRACT_HASH_SRC_LEN 20

const tezos_prefix_info TEZOS_PREFIX_BYTES[] = {
    /* addresses */
    { .prefix = {6, 161, 159}, .prefixlen = 3 }, /* tz1 */
    { .prefix = {6, 161, 161}, .prefixlen = 3 }, /* tz2 */
    { .prefix = {6, 161, 164}, .prefixlen = 3 }, /* tz3 */
    { .prefix = {2, 90, 121},  .prefixlen = 3 }, /* KT1 */

    /* public keys */
    { .prefix = {13, 15, 37, 217}, .prefixlen = 4 }, /* edpk */

    /* signatures */
    { .prefix = {9, 245, 205, 134, 18}, .prefixlen = 5 }, /* edsig */

    /* operation hash */
    { .prefix = {5, 116}, .prefixlen = 2 } /* o */
};

int hdnode_get_tezos_address(HDNode *node, char *address, int addrlen)
{
    uint8_t pkh[20];

    if (node->curve != get_curve_by_name(ED25519_NAME))
        return -1;

    hdnode_fill_public_key(node);

    if (blake2b(&node->public_key[1], 32, pkh, sizeof(pkh)) != 0)
        return -1;

    return b58cencode(pkh, sizeof(pkh), get_tezos_address_prefix(0), address, addrlen);
}

int hdnode_get_tezos_public_key(HDNode *node, char *public_key, int public_keylen)
{
    if (node->curve != get_curve_by_name(ED25519_NAME))
        return -1;

    hdnode_fill_public_key(node);

    return b58cencode(&node->public_key[1], 32, &TEZOS_PREFIX_BYTES[4], public_key, public_keylen);
}

bool tezos_sign_tx(HDNode *node, TezosSignTx *msg, TezosSignedTx *resp)
{
    hdnode_fill_public_key(node); // TODO: REMOVE THIS - temporary for not causing errors

    if (msg->has_transaction) {
        char destination[TEZOS_ADDRESS_LEN];
        get_tezos_address_from_contract(&msg->transaction.destination, destination);

        layoutRequireConfirmTx(destination, msg->transaction.amount);
        if (!signing_protect_button(false))
            return false;

        layoutRequireConfirmFee(msg->transaction.fee, msg->transaction.amount);
        if (!signing_protect_button(false))
            return false;
    } else if (msg->has_origination) {
        char source[TEZOS_ADDRESS_LEN];
        get_tezos_address_from_contract(&msg->transaction.source, source);

        layoutRequireConfirmOrigination(source);
        if (!signing_protect_button(false))
            return false;

        layoutRequireConfirmOriginationFee(msg->origination.balance, msg->origination.fee);
        if (!signing_protect_button(false))
            return false;
    } else if (msg->has_delegation) {
        char source[TEZOS_ADDRESS_LEN];
       	char delegate[TEZOS_ADDRESS_LEN];
	get_tezos_address_from_contract(&msg->delegation.source, source);
 
        // TODO: check if delegate exists (also check this in trezor-core)
 	get_tezos_address_by_tag(msg->delegation.delegate.bytes, delegate);

        if (strcmp(source, delegate) != 0) {
            layoutRequireConfirmDelegationBaker(delegate);
            if (!signing_protect_button(false))
                return false;

	    layoutRequireConfirmSetDelegate(msg->delegation.fee);
            if (!signing_protect_button(false))
                return false;
        } else {
            /* if account registers itself as a delegate */
            layoutRequireConfirmRegisterDelegate(source, msg->delegation.fee);
            if (!signing_protect_button(false))
                return false;
	}
    } else {
        fsm_sendFailure(FailureType_Failure_DataError, _("Invalid transaction type"));
	return false;
    }

    layoutProgressSwipe(_("Signing operations"), 0);

    uint8_t opbytes[1024];
    int datalen = tezos_get_operation_bytes(msg, opbytes);

    uint8_t wmopbytes[33];
    wmopbytes[0] = 3; /* watermark */
    memcpy(&wmopbytes[1], opbytes, datalen);

    uint8_t blaked[32];
    if (blake2b(wmopbytes, datalen+1, blaked, sizeof(blaked)) != 0)
        return false;

    uint8_t signature[64];

    ed25519_sign(blaked, sizeof(blaked), node->private_key,
		 &node->public_key[1], signature);

    memcpy(resp->sig_op_contents.bytes, opbytes, datalen);
    memcpy(resp->sig_op_contents.bytes + datalen, signature, 64);
    resp->sig_op_contents.size = datalen+64;

    uint8_t sig_op_contents_hash[32];
    if (blake2b(resp->sig_op_contents.bytes, datalen+64, sig_op_contents_hash, sizeof(sig_op_contents_hash)) != 0)
        return false;

    b58cencode(sig_op_contents_hash, sizeof(sig_op_contents_hash), &TEZOS_PREFIX_BYTES[6],
               resp->operation_hash, sizeof(resp->operation_hash));

    b58cencode(signature, 64, &TEZOS_PREFIX_BYTES[5], resp->signature, sizeof(resp->signature));

    resp->has_sig_op_contents = true;
    resp->has_signature = true;
    resp->has_operation_hash = true;

    return true;
}

bool signing_protect_button(bool confirm_only)
{
    if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, confirm_only)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing Canceled");
        return false;
    }
    return true;
}

const tezos_prefix_info *get_tezos_address_prefix(uint8_t tag)
{
    if (tag <= 2)
	return &TEZOS_PREFIX_BYTES[tag];
    fsm_sendFailure(FailureType_Failure_DataError, _("Invalid tag"));
    return NULL;
}

int get_tezos_address_from_contract(TezosContractID *contract, char *address)
{
    switch (contract->tag) {
        case TezosContractType_Implicit:
            return get_tezos_address_by_tag(contract->hash.bytes, address);
        case TezosContractType_Originated:
            return b58cencode(contract->hash.bytes, CONTRACT_HASH_SRC_LEN, &TEZOS_PREFIX_BYTES[3], address, TEZOS_ADDRESS_LEN);
        default:
            fsm_sendFailure(FailureType_Failure_DataError, _("Invalid tag in contract id"));
            return -1;
    }
}

int get_tezos_address_by_tag(const uint8_t *implicitaddr, char *address)
{
    switch (implicitaddr[0]) {
        case 0:
	case 1:
	case 2:
	    return b58cencode(&implicitaddr[1], CONTRACT_HASH_SRC_LEN, get_tezos_address_prefix(implicitaddr[0]), address, TEZOS_ADDRESS_LEN);
	default:
	    fsm_sendFailure(FailureType_Failure_DataError, _("Invalid tag in public key hash"));
	    return -1;
    }
}

void tezos_format_value(uint64_t value, char *formatted_value)
{
    bn_format_uint64(value, NULL, " XTZ", 6, 0, false, formatted_value, 20);
}

int b58cencode(const uint8_t *src, int srclen, const tezos_prefix_info *prefix, char *out, int outlen)
{
    uint8_t payload[srclen + prefix->prefixlen];

    /* concat prefix + src */
    memcpy(payload, prefix->prefix, prefix->prefixlen);
    memcpy(payload + prefix->prefixlen, src, srclen);

    if (base58_encode_check(payload, sizeof(payload), HASHER_SHA2D, out, outlen) == 0)
        return -1;

    return 0;
}

int tezos_get_operation_bytes(TezosSignTx *msg, uint8_t *out)
{
    int pos = 0;
    pos += tezos_memcpy(out, msg->branch.bytes, sizeof(msg->branch));

    if (msg->has_reveal) {
        pos += tezos_encode_byte(7, out+pos);
        pos += tezos_encode_contract_id(&msg->reveal.source, out+pos);
        pos += tezos_encode_zarith(msg->reveal.fee, out+pos);
        pos += tezos_encode_zarith(msg->reveal.counter, out+pos);
        pos += tezos_encode_zarith(msg->reveal.gas_limit, out+pos);
        pos += tezos_encode_zarith(msg->reveal.storage_limit, out+pos);
        pos += tezos_memcpy(out+pos, msg->reveal.public_key.bytes, 33);
    }

    if (msg->has_transaction) {
        pos += tezos_encode_byte(8, out+pos);
        pos += tezos_encode_contract_id(&msg->transaction.source, out+pos);
        pos += tezos_encode_zarith(msg->transaction.fee, out+pos);
        pos += tezos_encode_zarith(msg->transaction.counter, out+pos);
        pos += tezos_encode_zarith(msg->transaction.gas_limit, out+pos);
        pos += tezos_encode_zarith(msg->transaction.storage_limit, out+pos);
        pos += tezos_encode_zarith(msg->transaction.amount, out+pos);
	pos += tezos_encode_contract_id(&msg->transaction.destination, out+pos);

	// Let's assume there are no parameters for now
        pos += msg->transaction.has_parameters ?
            tezos_encode_data_true_prefix(
                msg->transaction.parameters.bytes,
                msg->transaction.parameters.size,
                out+pos
            ) : tezos_encode_byte(0, out+pos);
    } else if (msg->has_origination) {
        pos += tezos_encode_byte(9, out+pos);
        pos += tezos_encode_contract_id(&msg->origination.source, out+pos);
        pos += tezos_encode_zarith(msg->origination.fee, out+pos);
        pos += tezos_encode_zarith(msg->origination.counter, out+pos);
        pos += tezos_encode_zarith(msg->origination.gas_limit, out+pos);
        pos += tezos_encode_zarith(msg->origination.storage_limit, out+pos);
        pos += tezos_memcpy(out+pos, msg->origination.manager_pubkey.bytes, msg->origination.manager_pubkey.size);
        pos += tezos_encode_bool(msg->origination.spendable, out+pos);
        pos += tezos_encode_bool(msg->origination.delegatable, out+pos);
        pos += msg->origination.has_delegate ?
	    tezos_encode_data_true_prefix(
                msg->origination.delegate.bytes,
		msg->origination.delegate.size,
                out+pos
            ) : tezos_encode_byte(0, out+pos);

	// Let's assume there is no script now
	pos += msg->origination.has_script ?
            tezos_encode_data_true_prefix(
                msg->origination.script.bytes,
                msg->origination.script.size,
                out+pos
	    ) : tezos_encode_byte(0, out+pos);
    } else if (msg->has_delegation) {
        pos += tezos_encode_byte(10, out+pos);
        pos += tezos_encode_contract_id(&msg->delegation.source, out+pos);
        pos += tezos_encode_zarith(msg->delegation.fee, out+pos);
        pos += tezos_encode_zarith(msg->delegation.counter, out+pos);
        pos += tezos_encode_zarith(msg->delegation.gas_limit, out+pos);
        pos += tezos_encode_zarith(msg->delegation.storage_limit, out+pos);
	pos += msg->delegation.has_delegate ?
            tezos_encode_data_true_prefix(
                msg->delegation.delegate.bytes,
                msg->delegation.delegate.size,
                out+pos
            ) : tezos_encode_byte(0, out+pos);
    }

    return pos;
}

/* functions to encode data for signing */
int tezos_encode_bool(bool boolean, uint8_t *out)
{
    if (boolean)
        return tezos_encode_byte(255, out);
    return tezos_encode_byte(0, out);
}

int tezos_encode_data_true_prefix(uint8_t *data, int datalen, uint8_t *out)
{
    int res = tezos_encode_byte(255, out);
    return res + tezos_memcpy(out+res, data, datalen);
}
	
int tezos_encode_contract_id(TezosContractID *contract, uint8_t *out)
{
    int res = tezos_encode_byte(contract->tag, out);
    return res + tezos_memcpy(out+res, contract->hash.bytes, contract->hash.size);
}

int tezos_encode_zarith(uint64_t num, uint8_t *out)
{
    int pos = 0;
    while (1) {
        uint8_t byte = num & 127;
        num = num >> 7;

        if (num == 0) {
            pos += tezos_encode_byte(byte, out+pos);
	    break;
	}

	pos += tezos_encode_byte(byte | 128, out+pos);
    }
    return pos;
}

int tezos_encode_byte(uint8_t byte, uint8_t *out)
{
    uint8_t arr[] = {byte};
    return tezos_memcpy(out, arr, 1);
}

int tezos_memcpy(uint8_t *out, uint8_t *payload, int srclen)
{
    memcpy(out, payload, srclen);
    return srclen;
}

/* layouts */
void layoutRequireConfirmTx(char *destination, uint64_t amount)
{
    char formated_amount[20];
    const char **str = split_message((const uint8_t *)destination, strlen(destination), 19);
    tezos_format_value(amount, formated_amount);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
	    _("Confirm sending"),
            formated_amount,
            _("to:"),
            str[0],
            str[1],
            NULL
    );
}

void layoutRequireConfirmFee(uint64_t fee, uint64_t amount)
{
    char formatted_amount[20];
    char formatted_fee[20];
    tezos_format_value(amount, formatted_amount);
    tezos_format_value(fee, formatted_fee);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
            _("Confirm transaction"),
            formatted_amount,
            _("fee:"),
            formatted_fee,
            NULL,
            NULL
    );
}

void layoutRequireConfirmOrigination(char *address)
{
    const char **str = split_message((const uint8_t *)address, strlen(address), 19);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
	    _("Confirm origination"),
            _("Address:"),
            str[0],
            str[1],
	    NULL,
            NULL
    );
}

void layoutRequireConfirmOriginationFee(uint64_t balance, uint64_t fee)
{
    char formatted_balance[20];
    char formatted_fee[20];
    tezos_format_value(balance, formatted_balance);
    tezos_format_value(fee, formatted_fee);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
            _("Confirm Origination"),
	    _("Balance"),
            formatted_balance,
            _("Fee:"),
            formatted_fee,
            NULL
    );
}

void layoutRequireConfirmDelegationBaker(char *baker)
{
    const char **str = split_message((const uint8_t *)baker, strlen(baker), 19);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
	    _("Confirm delegation"),
	    NULL,
            _("Baker address:"),
            str[0],
            str[1],
            NULL
    );
}

void layoutRequireConfirmSetDelegate(uint64_t fee)
{
    char formatted_fee[20];
    tezos_format_value(fee, formatted_fee);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
            _("Confirm delegation"),
            NULL,
            _("Fee:"),
            formatted_fee,
            NULL,
            NULL
    );
}

void layoutRequireConfirmRegisterDelegate(char *address, uint64_t fee)
{
    char formatted_fee[20];
    const char **str = split_message((const uint8_t *)address, strlen(address), 19);
    tezos_format_value(fee, formatted_fee);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"),
            NULL,
            _("Confirm delegation"),
            _("Fee:"),
            formatted_fee,
            _("Address:"),
	    str[0],
	    str[1]
    );
}
