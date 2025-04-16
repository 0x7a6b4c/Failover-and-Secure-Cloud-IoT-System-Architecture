def tea(data, key):
    pad_length = 8 - len(data)
    data += b'\x00' * pad_length


    v0, v1 = int.from_bytes(data[:4], 'big'), int.from_bytes(data[4:8], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta, sum_ = 0x9E3779B9, 0
    for _ in range(32):  # 32 rounds
        sum_ = (sum_ + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
    return (v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big'))
