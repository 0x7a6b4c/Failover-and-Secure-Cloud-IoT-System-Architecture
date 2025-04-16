def tea_d(encrypted_data, key):
    if len(encrypted_data) != 8:
        raise ValueError("Encrypted data must be exactly 8 bytes")
    
    v0, v1 = int.from_bytes(encrypted_data[:4], 'big'), int.from_bytes(encrypted_data[4:8], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta, sum_ = 0x9E3779B9, 0x9E3779B9 * 32


    for _ in range(32):  # 32 rounds, reversed
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF


    decrypted = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
    return decrypted
