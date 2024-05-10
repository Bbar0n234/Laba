# import tables
import random


def print_sbox(sboxs):
    for block in sboxs:
        print(" ".join(val for row in block for val in row))


def generate_sboxes():
    standardTable = [list(range(256)) for _ in range(8)]

    sBoxs = [[[0] * 32] * 8 for _ in range(8)]
    for boxIndex in range(len(sBoxs)):
        j = 0
        random.shuffle(standardTable[boxIndex])
        print(standardTable[boxIndex])
        for row in range(len(sBoxs[boxIndex])):
            sBoxs[boxIndex][row] = [hex(val)[2:] for val in standardTable[boxIndex][j:j + 32]]
            j += 32

    print(sBoxs)
    return sBoxs


mySbox = generate_sboxes()
print_sbox(mySbox)

# print(len('11010100101001101110011001011000'))
