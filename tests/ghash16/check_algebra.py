"""Exhaustive bilinear-basis check of the Montgomery GHASH reduction."""
import json

MASK_64 = (1 << 64) - 1
MASK_128 = (1 << 128) - 1
REFLECTED_HIGH_LIMB = 0xC200000000000000


def carryless_product(left, right):
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
    return result


def montgomery_reduce(product):
    low = product & MASK_128
    high = product >> 128
    for _ in range(2):
        swapped = (low >> 64) | ((low & MASK_64) << 64)
        low = swapped ^ carryless_product(low & MASK_64, REFLECTED_HIGH_LIMB)
    return low ^ high


def reference_ghash_multiply(value, multiplier):
    result = 0
    for bit in range(127, -1, -1):
        if (multiplier >> bit) & 1:
            result ^= value
        value = (value >> 1) ^ ((0xE1 << 120) if value & 1 else 0)
    return result


def main():
    for left_bit in range(128):
        for right_bit in range(128):
            left, right = 1 << left_bit, 1 << right_bit
            actual = montgomery_reduce(carryless_product(left, right) << 1)
            expected = reference_ghash_multiply(left, right)
            if actual != expected:
                raise AssertionError((left_bit, right_bit, actual, expected))
    print(json.dumps({
        "basis_pairs": 128 * 128,
        "equal": True,
        "scope": "Every input pair by GF(2) bilinearity; an algebra check, "
                 "not an assembled machine-code proof.",
    }))


if __name__ == "__main__":
    main()
