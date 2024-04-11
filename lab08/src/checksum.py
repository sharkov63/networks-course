CHECKSUM_BLOCK_SIZE_BYTES = 2
CHECKSUM_BLOCK_SIZE_BITS = 8 * CHECKSUM_BLOCK_SIZE_BYTES


def getchecksum(data: bytes, max_checksum_size=CHECKSUM_BLOCK_SIZE_BITS * 2) -> int:
    checksum = 0
    for block in [data[offset:min(len(data), offset+CHECKSUM_BLOCK_SIZE_BYTES)] for offset in range(0, len(data), CHECKSUM_BLOCK_SIZE_BYTES)]:
        checksum += int.from_bytes(block, byteorder='little')
        checksum %= (1 << max_checksum_size)
    return checksum


def validatechecksum(data: bytes, max_checksum_size=CHECKSUM_BLOCK_SIZE_BITS * 2) -> bool:
    max_checksum_size_bytes = max_checksum_size // 8
    if len(data) < max_checksum_size_bytes:
        raise ValueError
    complement = int.from_bytes(data[:max_checksum_size_bytes], byteorder='little')
    checksum = (complement + getchecksum(data[max_checksum_size_bytes:], max_checksum_size)) % (1 << max_checksum_size)
    return checksum == (1 << max_checksum_size) - 1
