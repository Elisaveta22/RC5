from tkinter import *


class RC5:

    def __init__(self, w, R, key, strip_extra_nulls=False):
        self.w = w  # block size (32, 64 or 128 bits)
        self.R = R  # number of rounds (0 to 255)
        self.key = key  # key (0 to 2040 bits)
        self.strip_extra_nulls = strip_extra_nulls
        # some useful constants
        self.T = 2 * (R + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)

        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    def __lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def __rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def __const(self):  # constants generation
        if self.w == 16:
            return 0xB7E1, 0x9E37  # return P, Q values
        elif self.w == 32:
            return 0xB7E15163, 0x9E3779B9
        elif self.w == 64:
            return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

    def __keyAlign(self):
        if self.b == 0:  # key is empty
            self.c = 1
        elif self.b % self.w8:
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # fill key with \x00 bytes
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):
        P, Q = self.__const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def encryptBlock(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.R + 1):
            A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def decryptBlock(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        for i in range(self.R, 0, -1):
            B = self.__rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def encryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    text = text.ljust(self.w4, b'\x00')
                    run = False
                text = self.encryptBlock(text)
                out.write(text)

    def encrypt(self, text):
        output_text = b""
        run = True
        text_byte_list = text.encode()
        offset = 0

        while run:
            selected_bytes = text_byte_list[offset:(offset + self.w4)]
            offset += self.w4

            if len(selected_bytes) == 0:
                break
            if len(selected_bytes) != self.w4:
                selected_bytes = selected_bytes.ljust(self.w4, b'\x00')
                run = False
            encrypted_block = self.encryptBlock(selected_bytes)
            output_text += encrypted_block

        lbl.configure(text="Зашифрованный текст:" + output_text.decode('ISO-8859-1'))
        txt_to_decode_word.delete(0, END)
        txt_to_decode_word.insert(0, output_text.decode('ISO-8859-1'))

    def decryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            while True:
                text = inp.read(self.w4)
                if not text:
                    break
                text = self.decryptBlock(text)
                if self.strip_extra_nulls:
                    text = text.rstrip(b'\x00')
                out.write(text)

    def decrypt(self, bytestring):
        bytestring = bytestring.encode('ISO-8859-1')

        offset = 0
        out_bytes = b""
        while True:
            selected_bytes = bytestring[offset:(offset + self.w4)]
            offset += self.w4

            if len(selected_bytes) == 0:
                break

            decrypted_text = self.decryptBlock(selected_bytes)
            if self.strip_extra_nulls:
                decrypted_text = decrypted_text.rstrip(b'\x00')

            out_bytes += decrypted_text

        lbl2.configure(text="Расшифрованный текст:" + out_bytes.decode())

    def encryptBytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w4]
            if len(temp) != self.w4:
                data = data.ljust(self.w4, b'\x00')
                run = False
            res += self.encryptBlock(temp)
            data = data[self.w4:]
            if not data:
                break
        return res

    def decryptBytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w4]
            if len(temp) != self.w4:
                run = False
            res += self.decryptBlock(temp)
            data = data[self.w4:]
            if not data:
                break
        return res.rstrip(b'\x00')


def onEncryptClick():
    word = txt_word.get()
    w = int(tkvar.get())   # todo
    R = int(txt_round.get())
    key = txt_encoding_key.get()

    obj = RC5(w, R, key.encode())
    obj.encrypt(word)


def onDecryptClick():
    word = txt_to_decode_word.get()
    w = int(tkvar.get())  # todo
    R = int(txt_round.get())
    key = txt_encoding_key.get()

    obj = RC5(w, R, key.encode())
    obj.decrypt(word)


window = Tk()
window.geometry('600x400')
window.title("RC5 Cipher")

# ENCODE


# Create a Tkinter variable
tkvar = StringVar(window)

# Dictionary with options
choices = {'16', '32', '64'}
tkvar.set('32')# set the default option

Label(window, text="Длина слова в битах: ").grid(column=0, row=0)
popupMenu = OptionMenu(window, tkvar, *choices)
popupMenu.grid(column=1, row=0, padx=20, pady=10)

# on change dropdown value
def change_dropdown(*args):
    print( tkvar.get() )

# link function to change dropdown
tkvar.trace('w', change_dropdown)

Label(window, text="Текст для шифрования: ").grid(row=1)

txt_word = Entry(window, width=30, font=30)
txt_word.grid(column=1, row=1, padx=20, pady=10)

Label(window, text="Количество раундов: ").grid(row=2)  # R

txt_round = Entry(window, width=30, font=30)
txt_round.grid(column=1, row=2, padx=20, pady=10)

Label(window, text="Ключ для шифрования:").grid(row=3)

txt_encoding_key = Entry(window, width=30, font=30)
txt_encoding_key.grid(column=1, row=3, padx=20, pady=0)

lbl = Label(window, font=("Arial Bold", 12))
lbl.grid(column=1, row=5)

# DECODE

Label(window, text="Текст для расшифровки: ").grid(row=6)

txt_to_decode_word = Entry(window, width=30, font=30)
txt_to_decode_word.grid(column=1, row=6, padx=20, pady=10)

Label(window, text="Ключ для расшифровки:").grid(row=7)

txt_decoding_key = Entry(window, width=30, font=30)
txt_decoding_key.grid(column=1, row=7, padx=20, pady=0)

lbl2 = Label(window, font=("Arial Bold", 12))
lbl2.grid(column=1, row=10)

# Object create

btn = Button(window, text="Зашифровать", font=12, command=onEncryptClick)
btn.grid(column=1, row=4, padx=5, pady=5)

btn2 = Button(window, text="Расшифровать", font=12, command=onDecryptClick)
btn2.grid(column=1, row=9, padx=5, pady=5)
window.mainloop()