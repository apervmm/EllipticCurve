"""

 Almas Perneshev
 Math 10
 Project Interactive Elliptic Curve Encryption/Decryption

"""

from tkinter import *
from random import randint
from hashlib import sha256
from eliptic_curve import EllipticCurve, ECPoint


def keygen():
    """ secp256k1 curve  - Bitcoin curve from slides """
    prime = int('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16)  # large prime in base 16

    # Any Shared Public Point Whose Order is Very Large Number
    point = ECPoint(int('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
                    int('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16))
    ecurve = EllipticCurve(prime, point, 0, 7)  # y^2 = x^3 + 7

    # generate private key
    private_k = randint(1, prime)  # private key
    public_k = ecurve.mul(point, private_k)  # public key
    return private_k, ecurve, point, prime, public_k


def encrypt(message, e_curve, point, prime, public_key):
    """
        input: message, ECC, GenPoint, prime number, public_key
        return: cypher
    """

    number_ecc = randint(1, prime)  # random int k
    c1 = e_curve.mul(point, number_ecc)  # kG
    hs = sha256(repr(e_curve.mul(public_key, number_ecc)).encode('utf-8')).digest()  # encrypting message based on point
    c2 = bytearray([i ^ j for i, j in zip(bytes(message), bytes(hs))])  # second cipher
    return (c1, bytes(c2))  # returning cipher point


def decrypt(cipher, private_key, e_curve):
    """
        input: cipher, private_key , e_curve
        return: decrypted message
    """
    cipher1, cipher2 = cipher
    s = e_curve.mul(cipher1, private_key)  # point multiplication
    hs = sha256(repr(s).encode('utf-8')).digest()  # kP_B - kGn_B
    message = bytearray([i ^ j for i, j in zip(cipher2, hs)])  # decrypting point(Pm + kP_B - kGn_B)
    return bytes(message)


def main():
    private_key, e_curve, point, prime, public_key = keygen()
    cipher = (point, bytes())

    window = Tk()
    window.title("Elliptic Curve Message Encryption by Almas Perneshev")

    def send():
        message = messageEntry.get("1.0", "end")
        print("Message: ", message)
        message = message.encode('utf-8')
        cipher = encrypt(message, e_curve, point, prime, public_key)
        encryptedEntry.insert(0.0, cipher)
        print("Encripted: {}".format(cipher))
        decrypted = decrypt(cipher, private_key, e_curve)
        recievedEntry.insert(0.0, decrypted)
        print('Decrypted:\t{}'.format(decrypted.decode()))

    def clear():
        messageEntry.delete(0.0, END)
        encryptedEntry.delete(0.0, END)
        recievedEntry.delete(0.0, END)

    Label(window, text="Enter your message", font=("Arial", 25)).grid(row=0, column=0, columnspan=2)

    Label(window, text="Message: ", font=("Arial", 20), width=20).grid(row=1, column=0)
    messageEntry = Text(window, height=5)
    messageEntry.grid(row=1, column=1)
    messageButton = Button(window, text="Send", command=send, width=10, height=5)
    messageButton.grid(row=1, column=2)

    Label(window, text="Encrypted: ", font=("Arial", 20)).grid(row=2, column=0)
    encryptedEntry = Text(window, height=5)
    encryptedEntry.grid(row=2, column=1)

    Label(window, text="Decrypted: ", font=("Arial", 20)).grid(row=3, column=0)
    recievedEntry = Text(window, height=5)
    recievedEntry.grid(row=3, column=1)

    Button(window, text="Clear", width=10, height=5, command=clear).grid(row=4, columnspan=2)

    window.mainloop()


if __name__ == '__main__':
    main()
