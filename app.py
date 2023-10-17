#!/usr/bin/env python
"""Extract the public key from the private key and write to a file.
"""
import streamlit as st
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import sys



st.title("Digital Signature and Verifier")


#message = "I want this stream signed"
message = st.text_area("Enter message to sign:")
digest = SHA256.new()
digest.update(message.encode('utf-8'))

# Load private key previouly generated
private_key = None
with open ("private_key.pem", "r") as myfile:
    private_key = RSA.importKey(myfile.read())

# Sign the message
signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)

# sig is bytes object, so convert to hex string.
# (could convert using b64encode or any number of ways)
st.write("Signature: => ", sig.hex())


message_to_verify = st.text_area("Enter message to verify:")
digest = SHA256.new()
digest.update(message_to_verify.encode('utf-8'))

sig = st.text_area('Signature to verify:')
sig = bytes.fromhex(sig)

public_key = PKCS1_v1_5.new(private_key.publickey())
verified = public_key.verify(digest, sig)

if verified:
    st.success('Successfully verified message')
else:
    st.error('FAILED')
