#!/bin/bash
# metadata_protect.sh

encrypt_metadata() {
    challenge=$(openssl rand 32 | xxd -p -c 32)
    aes_key=$(ykchalresp -2 -x "$challenge")
    
    openssl enc -aes-256-cbc -in /tpmdata/provisioning.json \
        -out /tpmdata/provisioning.enc -k "$aes_key"
    
    echo "$challenge" > /tpmdata/.challenge
    chmod 600 /tpmdata/provisioning.enc /tpmdata/.challenge
    rm /tpmdata/provisioning.json
}

decrypt_metadata() {
    challenge=$(cat /tpmdata/.challenge)
    aes_key=$(ykchalresp -2 -x "$challenge")
    
    openssl enc -aes-256-cbc -d -in /tmpdata/provisioning.enc \
        -out /tpmdata/provisioning.json -k "$aes_key"
}