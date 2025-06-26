def input_positive_number():
    positive_number = int(input("Enter a positive number: "))
    bits_size = int(input("Enter lenght of bits: "))

    return positive_number , bits_size


def number_to_binary(positive_number, bits_size):
    binary_number = f'{positive_number:0{bits_size}b}'
    return binary_number


def binary_to_negative(binary_expression, bits_size):
    binary_expression = ~int(binary_expression, base=2) + 1 & (1 << bits_size) - 1
    negative_number_binary = f'{binary_expression:0{bits_size}b}'
    return negative_number_binary

def __main__():
    positive_number , bits_size = input_positive_number()
    binary_number = number_to_binary(positive_number, bits_size)
    print(f'The positive number number in binary {binary_number}')
    negative_number_binary = binary_to_negative(binary_number, bits_size)
    print(f'The negative  number in binary {negative_number_binary}')

if __name__ == __main__:
    __main__()