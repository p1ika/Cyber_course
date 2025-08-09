from PIL import Image


File_path = r'G:\PyCharm Community Edition 2023.2.4\Cyber\Steganography_keylogger\KeyLog.py'
with open(File_path, 'rb') as file:
    File_byte = file.read()

Bits_string = ''
for Byte in File_byte:
    Bits_string += f'{Byte:08b}'
print(Bits_string)

img = Image.open('TreeWithCode.png')

Bit_idx = 0
Pixels = img.load()
width, height = img.size
for wid in range(width):
    for hig in range(height):
        if Bit_idx >= len(Bits_string):
            break
        r, g ,b, *rest = Pixels[wid,hig]
        r = r & ~1 | int(Bits_string[Bit_idx])
        Pixels[wid,hig] = r , g , b
        Bit_idx += 1
        if Bit_idx >= len(Bits_string):
            break

img.save('TreeWithCode_stego.png')





