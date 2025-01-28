import nilql
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

#####################################################
# Step 1: Generate ECDSA key pair                   #
#####################################################
ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
ecdsa_public_key = ecdsa_private_key.public_key()

#####################################################
# Step 2: Secret share the private key using nilql  #
#####################################################
cluster = {'nodes': [{}, {}, {}]}

# ECDSA Private Key Secret Sharing
ecdsa_private_bytes = ecdsa_private_key.private_numbers().private_value.to_bytes(32, 'big')
ecdsa_secret_key = nilql.SecretKey.generate(cluster, {'store': True})

# Convert bytes to hex string for nilql.encrypt
ecdsa_private_str = ecdsa_private_bytes.hex()

# For multi-node clusters, the ciphertext is secret-shared across the nodes using XOR
# Each element in ecdsa_ciphertext is a hex-encoded share that should be sent
# to a different nilDB node.
ecdsa_ciphertext = nilql.encrypt(ecdsa_secret_key, ecdsa_private_str)
print(f"ECDSA shares to be sent to different nodes: {ecdsa_ciphertext}")

#####################################################
# Step 3: Reconstruct the private key using nilql   #
#####################################################
reconstructed_ecdsa_private_hex = nilql.decrypt(ecdsa_secret_key, ecdsa_ciphertext)
reconstructed_ecdsa_private_bytes = bytes.fromhex(reconstructed_ecdsa_private_hex)

# Reconstruct ECDSA Private Key
reconstructed_ecdsa_private_key = ec.derive_private_key(
    int.from_bytes(reconstructed_ecdsa_private_bytes, 'big'), ec.SECP256K1()
)

# Verify that the reconstructed key matches the original key
assert ecdsa_private_bytes == reconstructed_ecdsa_private_bytes, "ECDSA private key reconstruction failed"

#####################################################
# Step 4: Compute a signature over a message        #
#####################################################
message = b"Nillion is the future of secure data sharing!"

# ECDSA Signature and Verification
ecdsa_signature = reconstructed_ecdsa_private_key.sign(
    message, ec.ECDSA(hashes.SHA256())
)
# Verify ECDSA signature
ecdsa_public_key.verify(
    ecdsa_signature,
    message,
    ec.ECDSA(hashes.SHA256())
)
print("ECDSA Signature verified successfully!")
print("ECDSA Signature:", ecdsa_signature) 