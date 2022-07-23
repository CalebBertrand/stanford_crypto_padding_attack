import re
import copy
import requests
from bitstring import BitArray


BITS_IN_BLOCK = 8 * 16  # 1 AES block = 16 bytes
TARGET = 'http://crypto-class.appspot.com/po?er='
CYPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
CYPHERTEXT_BLOCKS = re.findall('..'*16, CYPHERTEXT)


def query_padding_oracle(__query: str) -> bool:
    res = requests.get(TARGET + __query)  # Send HTTP request to server
    if res.status_code == 404:
        return True  # Good padding
    elif res.status_code == 403:
        return False  # Bad padding
    else:
        return True  # On the off chance that the MAC is correct


def build_pad(__byte_index: int) -> BitArray:
    pad_num = f'uint:8={__byte_index + 1}, '
    leading_zeros = f'0x{"00" * (15 - __byte_index)}, ' if __byte_index < 15 else ''
    return BitArray(leading_zeros + pad_num * (__byte_index + 1))


def build_guess(__guess: int, __current_block_plaintext: BitArray) -> BitArray:
    if guess > 255:
        raise Exception(f'No valid ascii character sequence found for this block.')
    full_array = BitArray(f'uint:8={__guess}')
    full_array.append(__current_block_plaintext)
    full_array.prepend(BITS_IN_BLOCK - 8 - __current_block_plaintext.len)
    return full_array


def build_query(__block_index: int, __next_guess: BitArray, __pad: BitArray) -> str:
    block_strings = copy.deepcopy(CYPHERTEXT_BLOCKS)
    modified_prev_block = BitArray(f'0x{block_strings[__block_index - 1]}') ^ __next_guess ^ __pad
    block_strings[__block_index - 1] = modified_prev_block.hex
    # Drop any blocks after current so that the pad is at the "end".
    # Drop any blocks before the prev as well since they are not needed.
    return "".join(block_strings[__block_index - 1:__block_index + 1])


plaintext = ""
for block_index in range(1, len(CYPHERTEXT_BLOCKS)):  # Exclude first block, it's the IV
    block_guesses = BitArray(0)  # Holds the string of guesses which return true from the padding oracle
    for byte_index in range(16):
        pad_array = build_pad(byte_index)
        guess = 0
        guess_array = build_guess(guess, block_guesses)
        while not query_padding_oracle(build_query(block_index, guess_array, pad_array)):
            print(f'Guessed: {guess}')
            guess += 1
            guess_array = build_guess(guess, block_guesses)
        block_guesses.prepend(BitArray(f'uint:8={guess}'))
        print(f'Current Block Decyphered: {block_guesses.hex}')
    plaintext += bytearray.fromhex(block_guesses.hex).decode()
    print(f'Current Plaintext Decyphered: {plaintext}')

