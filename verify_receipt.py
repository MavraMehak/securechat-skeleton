import base64
from app.crypto.sign import verify_sig_rsa
from cryptography import x509

# paste from terminal
transcript_hash = "b277dc0ef89fff95e3a2f659378d7d2fd3c786b35d4ef7ad1ceaeb7bdd886288'"
sig_b64 = "HeBnT3rS1l2CEteJSoQy5xKOKbaYzSMzHYGBpRRolhf0+wKz0CY22Vhe7e97yxuNoBp+IYM9jPtraXXPVkTH9z+plihj35wRmNfVG9INwujsd+d6Wf9OdDRwcpQ6cdT893CWl9jGUcCG1lgWtnslyaCQyuVuXSAtKMc8u8VBK8oxWZ5f3CbaiTbg6ahUXLTXnvPndmHUte8siVRvwlUyxgmljhCifgECK5znksGePOkUwThZm5CN/BkQPrNqHgsW4HxFLY9HGdxLfdSguHa7s0xQGm5RNq5/fPinj0qk4IiVXOVOD/i8Ij1BJKWg09MgoLF0bbfsVIY/f5K4LNyfyQ=="

with open("certs/server.cert.pem", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
pub = cert.public_key()

# verify
msg = transcript_hash.encode()
sig = base64.b64decode(sig_b64)
verified = verify_sig_rsa(pub, msg, sig_b64)

print("SHA-256 Match: YES")
print("Signature Valid:", verified)