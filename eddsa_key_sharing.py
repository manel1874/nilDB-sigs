import nilql
from cryptography.hazmat.primitives.asymmetric import ed25519

#####################################################
# Step 1: Generate EdDSA key pair                   #
#####################################################
eddsa_private_key = ed25519.Ed25519PrivateKey.generate()
eddsa_public_key = eddsa_private_key.public_key()

#####################################################
# Step 2: Secret share the private key using nilql  #
#####################################################
cluster = {'nodes': [{}, {}, {}]}

# EdDSA Private Key Secret Sharing
eddsa_private_bytes = eddsa_private_key.private_bytes_raw()
eddsa_secret_key = nilql.SecretKey.generate(cluster, {'store': True})

# Convert bytes to hex string for nilql.encrypt
eddsa_private_str = eddsa_private_bytes.hex()

# For multi-node clusters, the ciphertext is secret-shared across the nodes using XOR
# Each element in eddsa_ciphertext is a hex-encoded share that should be sent
# to a different nilDB node.
eddsa_ciphertext = nilql.encrypt(eddsa_secret_key, eddsa_private_str)
print(f"EdDSA shares to be sent to different nodes: {eddsa_ciphertext}")

#####################################################
# Step 3: Reconstruct the private key using nilql   #
#####################################################
reconstructed_eddsa_private_hex = nilql.decrypt(eddsa_secret_key, eddsa_ciphertext)
reconstructed_eddsa_private_bytes = bytes.fromhex(reconstructed_eddsa_private_hex)

# Reconstruct EdDSA Private Key
reconstructed_eddsa_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
    reconstructed_eddsa_private_bytes
)

# Verify that the reconstructed key matches the original key
assert eddsa_private_bytes == reconstructed_eddsa_private_bytes, "EdDSA private key reconstruction failed"

#####################################################
# Step 4: Compute a signature over a message        #
#####################################################
message = b"Nillion is the future of secure data sharing!"

# EdDSA Signature and Verification
eddsa_signature = reconstructed_eddsa_private_key.sign(message)
# Verify EdDSA signature
eddsa_public_key.verify(
    eddsa_signature,
    message
)
print("EdDSA Signature verified successfully!")
print("EdDSA Signature:", eddsa_signature) 