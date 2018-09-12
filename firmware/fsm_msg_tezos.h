void fsm_msgTezosGetAddress(TezosGetAddress *msg)
{
    CHECK_INITIALIZED

    CHECK_PIN

    RESP_INIT(TezosAddress)

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) {
        fsm_sendFailure(Failure_FailureType_Failure_ProcessError, _("Failed to derive private key"));
        return;
    }

    if (hdnode_get_tezos_address(node, resp->address, sizeof(resp->address)) != 0)
        return;

    resp->has_address = true;

    if (msg->has_show_display && msg->show_display) {
        char desc[16];
        strlcpy(desc, "Address:", sizeof(desc));

        if (!fsm_layoutAddress(resp->address, desc, true, 0, msg->address_n, msg->address_n_count)) {
            return;
        }
    }

    msg_write(MessageType_MessageType_TezosAddress, resp);

    layoutHome();
}

void fsm_msgTezosGetPublicKey(TezosGetPublicKey *msg)
{
    CHECK_INITIALIZED

    CHECK_PIN

    RESP_INIT(TezosPublicKey)

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) {
        fsm_sendFailure(Failure_FailureType_Failure_ProcessError, _("Failed to derive private key"));
        return;
    }

    if (hdnode_get_tezos_public_key(node, resp->public_key, sizeof(resp->public_key)) != 0)
        return;

    resp->has_public_key = true;

    if (msg->has_show_display && msg->show_display) {
        char desc[13];
        const char **str = split_message((const uint8_t *)resp->public_key, 55, 16);
        strlcpy(desc, "Public Key:", sizeof(desc));
        layoutDialogSwipe(&bmp_icon_question, NULL, _("Continue"), NULL,
                          desc, str[0], str[1], str[2], str[3], NULL);
        if (!protectButton(ButtonRequest_ButtonRequestType_ButtonRequest_PublicKey, true)) {
            fsm_sendFailure(Failure_FailureType_Failure_ActionCancelled, NULL);
            layoutHome();
            return;
        }
    }

    msg_write(MessageType_MessageType_TezosPublicKey, resp);

    layoutHome();
}

void fsm_msgTezosSignTx(TezosSignTx *msg)
{
    CHECK_INITIALIZED

    CHECK_PIN

    RESP_INIT(TezosSignedTx)

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) {
        fsm_sendFailure(Failure_FailureType_Failure_ProcessError, _("Failed to derive private key"));
        return;
    }

    hdnode_fill_public_key(node);

    if (tezos_sign_tx(node, msg, resp)) {
        msg_write(MessageType_MessageType_TezosSignedTx, resp);
    }

    layoutHome();
}
