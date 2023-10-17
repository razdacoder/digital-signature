import streamlit as st
import hashlib
import hmac
import base64



st.title("Digital Signature and Verifier")


message = st.text_area("Enter message to sign:")
digest = hashlib.sha256(message.encode()).digest()

# Load private key previouly generated
private_key = '*pi4xk8m2+xe^0t6ogmga2e^e))z2t6%wj)ogp@hf0o_+-)ibq'


# Sign the message
if st.button("Sign Message"):
    signature = hmac.new(private_key.encode(), digest, hashlib.sha256).hexdigest()
    encoded_signature = base64.b64encode(signature.encode()).decode()
    st.write("Signature: => ", encoded_signature)



message_to_verify = st.text_area("Enter message to verify: ")
signature = st.text_area('Signature to verify: ')
if st.button("Verify Signature"):
    try:
        signature = base64.b64decode(signature.encode()).decode()
        digest = hashlib.sha256(message_to_verify.encode('utf-8')).digest()
        verified = hmac.new(private_key.encode(), digest, hashlib.sha256).hexdigest() == signature
        if verified:
            st.success("Successfully verified message")
        else:
            st.error("Failed to verify message: This message may have been tempared with.")
    except:
        st.error("Failed to verify message: This message may have been tempared with.")
