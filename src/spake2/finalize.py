from hashlib import sha256

def finalize_SPAKE2(idA, idB, X_msg, Y_msg, K_bytes, pw):
    transcript = b"".join([sha256(idA).digest(), sha256(idB).digest(),
                           X_msg, Y_msg, K_bytes, pw])
    key = sha256(transcript).digest()
    return key

def finalize_SPAKE2_symmetric(idSymmetric, msg1, msg2, K_bytes, pw):
    # since we don't know which side is which, we must sort the messages
    first_msg, second_msg = sorted([msg1, msg2])
    transcript = b"".join([sha256(idSymmetric).digest(),
                           first_msg, second_msg, K_bytes,
                           pw])
    key = sha256(transcript).digest()
    return key
