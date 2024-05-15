import tables
import time

BLOCK_LENGTH = 64
KEY_LENGTH = 64
HALF_BLOCK = round(BLOCK_LENGTH / 2)

sBoxTable = tables.sBoxs


def text_to_binary(text):
    '''
    Переводит исходное сообщение в двоичный формат
    '''
    return ''.join(format(ord(char), '08b') for char in text)


def binary_to_text(binary):
    '''
    Переводит сообщение из двоичного формата в нормальный вид
    '''
    while len(binary) >= 8 and binary[-4:] == '0000':
        binary = binary[:-4]

    chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]

    # Convert each 8-bit chunk back to a character and join them
    text = ''.join(chr(int(chunk, 2)) for chunk in chunks)
    return text


def chunk_into_64_bits(input_data):
    '''
    Разбивает входные данные на блоки блиной 64 бит
    '''
    blocks = [input_data[i:i + 64] if len(input_data[i:i + 64]) == 64 else zero_pad(input_data[i:i + 64]) for i in
              range(0, len(input_data), 64)]
    return blocks


def zero_pad(input_block):
    '''
    Добавляет нули в блок данных, чтобы он стал длинной 64 бит
    '''
    while len(input_block) < 64:
        input_block += "0"
    return input_block


def xor_bin_operation(text, key):
    '''
    Побитовое исключающее ИЛИ
    Возвращает 1 если биты одинаковые и 0 в противном случае
    '''
    if (len(text) != len(key)):  #
        raise Exception(f"Length of key and text is different!\nText length is {len(text)}\nKey length is {len(key)}")

    encrypted_text = ''
    for i in range(len(text)):
        encrypted_text += str(int(text[i]) ^ int(key[i]))

    return encrypted_text


def cyclic_left_shift(bits, shift_amount):
    '''
    Циклический сдвиг влево(Шифрование)
    '''
    return bits[shift_amount:] + bits[:shift_amount]


def divide_block_by2(block):
    '''
    Делит блок надвое
    '''
    result_block = [block[i:i + HALF_BLOCK] for i in range(0, round(len(block)), HALF_BLOCK)]
    return result_block


def process_left_block(last_8_bits, octet_index):
    '''
    Применяет перестановку к левому блоку
    '''
    selected_sbox = sBoxTable[octet_index]
    output_bits = []
    for i in range(0, len(last_8_bits), round(len(last_8_bits) / 4)):
        sbox_row = last_8_bits[i:i + 3]
        sbox_col = last_8_bits[i + 3:i + 8]
        output_bits.extend(bin(int(selected_sbox[int(sbox_row, 2)][int(sbox_col, 2)], 16))[2:].zfill(8))
    returnedBlock = ''.join(output_bits)

    return returnedBlock


def bin_text_to_string(blocks):
    '''
    Конкатенирует все блоки и убирает незначащие нули
    '''
    concatenated = ''

    for block in blocks:
        for part in block:
            concatenated += ''.join(part)

    concatenated = concatenated[:-(len(concatenated) % 8)] if len(concatenated) % 8 != 0 else concatenated

    return binary_to_text(concatenated)


def bin_text_to_hex(block):
    resulted_hex = ''
    if isinstance(block[0], list):
        for sub_block in block:
            for part in sub_block:
                resulted_hex += hex(int(part, 2))[2:]
    elif isinstance(block[0], str):
        for part in block:
            resulted_hex += hex(int(part, 2))[2:]

    return resulted_hex


def hex_to_bin_text(hex_string):
    bin_text = ''
    for hex_char in hex_string:
        bin_text += bin(int(hex_char, 16))[2:].zfill(4)
    return bin_text


def analyse_entered_value(text_to_encrypt, key, is_hex_input_value=False):
    '''
        \brief Функция которая анализирует текст и ключ для шифрования

        \param [in] text_to_encrypt Исходный текст в буквенном формате
        \param [in] key Ключ для шифрования в буквенном формате
        \param [in] is_hex_input_value Флаг, который указывает в каком формате входное значение

        \return Список пар блоков по 32 бита, а также ключ в бинарном формате.

         \warning Не принимает отрицательные значения
    '''
    if not is_hex_input_value:
        bin_text = text_to_binary(text_to_encrypt)
        bin_key = text_to_binary(key)
    else:
        bin_text = hex_to_bin_text(text_to_encrypt)
        bin_key = text_to_binary(key)

    if len(bin_text) > 64:
        bin_text = chunk_into_64_bits(bin_text)
    elif len(bin_text) < 64:
        bin_text = [zero_pad(bin_text)]
    else:
        bin_text = [bin_text]

    if len(bin_key) > 64:
        bin_key = [chunk_into_64_bits(bin_key)[0]]
    elif len(bin_key) < 64:
        bin_key = [zero_pad(bin_key)]
    else:
        bin_key = [bin_key]

    result_bin_text = []
    for binPart in bin_text:
        result_bin_text.append(divide_block_by2(binPart))

    result_bin_key = divide_block_by2(bin_key[0])

    return result_bin_text, result_bin_key


def khafre_encryption(block, round=8):
    round_number = 8 - round
    changed_left_block = process_left_block(block[0], round_number)
    xor_right_and_changed_left = xor_bin_operation(changed_left_block, block[1])

    if round_number == 2 or round_number == 3:
        shift_amount = 8
    elif round_number == 6 or round_number == 7:
        shift_amount = 24
    else:
        shift_amount = 16

    left_block = cyclic_left_shift(block[0], shift_amount)

    resulted_block = [xor_right_and_changed_left, left_block]
    if round == 1:
        return resulted_block
    return khafre_encryption(resulted_block, round - 1)


def khafre_cipher(text_to_encrypt, key, rounds):
    bin_text_to_encrypt, bin_key = analyse_entered_value(text_to_encrypt, key)

    for i in range(len(bin_text_to_encrypt)):
        for j in range(len(bin_text_to_encrypt[i])):
            bin_text_to_encrypt[i][j] = xor_bin_operation(bin_text_to_encrypt[i][j], bin_key[j])

    for _ in range(rounds):
        for i in range(len(bin_text_to_encrypt)):
            bin_text_to_encrypt[i] = khafre_encryption(bin_text_to_encrypt[i])
            for j in range(len(bin_text_to_encrypt[i])):
                bin_text_to_encrypt[i][j] = xor_bin_operation(bin_text_to_encrypt[i][j], bin_key[j])

    encrypted_string = bin_text_to_hex(bin_text_to_encrypt)

    print(f"\nEncrypted text: \n\t{encrypted_string}\n\n")

    return encrypted_string


def khafre_decryption(block, round=0):
    round_number = 7 - round

    if round_number == 2 or round_number == 3:
        shift_amount = 8
    elif round_number == 6 or round_number == 7:
        shift_amount = 24
    else:
        shift_amount = 16

    xored_right_and_changed_left = block[0]
    reversed_shifted_left_block = cyclic_left_shift(block[1], -shift_amount)

    changed_left_block = process_left_block(reversed_shifted_left_block, round_number)

    right_block = xor_bin_operation(xored_right_and_changed_left, changed_left_block)

    if round == 7:
        return [reversed_shifted_left_block, right_block]

    resultedBlock = [reversed_shifted_left_block, right_block]
    return khafre_decryption(resultedBlock, round + 1)


def khafre_decipher(text_to_decrypt, key, rounds):
    bin_text_to_decrypt, bin_key = analyse_entered_value(text_to_decrypt, key, True)

    for _ in range(rounds):
        for i in range(len(bin_text_to_decrypt)):
            for j in range(len(bin_text_to_decrypt[i])):
                bin_text_to_decrypt[i][j] = xor_bin_operation(bin_text_to_decrypt[i][j], bin_key[j])
            bin_text_to_decrypt[i] = khafre_decryption(bin_text_to_decrypt[i])

    for i in range(len(bin_text_to_decrypt)):
        for j in range(len(bin_text_to_decrypt[i])):
            bin_text_to_decrypt[i][j] = xor_bin_operation(bin_text_to_decrypt[i][j], bin_key[j])

    decrypted_string = bin_text_to_string(bin_text_to_decrypt)

    print(f"\n\nDecrypted text: \n\t{decrypted_string}\n\n")

    return decrypted_string


def main():
    while (True):
        print("Choose an option:")
        print("\t1. Encrypt")
        print("\t2. Decrypt")
        print("\t0. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            text = str(input("Enter text to encrypt: "))
            key = str(input(
                "Enter key-> "))
            while True:
                try:
                    rounds = int(input(
                        "Rounds of encryption-> "))
                    break
                except ValueError:
                    print("Please enter a valid number for rounds.")

            start_time = time.time()
            khafre_cipher(text, key, rounds)
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Время выполнения шифрования: {execution_time} секунд")
        elif choice == '2':
            while True:
                try:
                    text = str(input(
                        "Enter text to decrypt: "))
                    break
                except ValueError as e:
                    print(e)

            key = str(input("Enter key-> "))

            while True:
                try:
                    rounds = int(input(
                        "Rounds of decryption-> "))
                    break
                except ValueError:
                    print("Please enter a valid number for rounds.")

            start_time = time.time()
            khafre_decipher(text, key, rounds)
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Время выполнения дешифрования: {execution_time} секунд")
        elif choice == '0':
            print("Closing the program ...")
            return
        else:
            print('\n\tYour entered incorrect number of menu options\n')


if __name__ == "__main__":
    main()
