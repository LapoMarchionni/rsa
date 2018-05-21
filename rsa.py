import random
import time


class RSA:
    """RSA Scheme.
    Encrypt using as default the public key and decrypt using as default
    the private key.

    Args:
        prime_lenght: prime lenght used for the keys generations.
            [default: 10^100]
    """

    def __init__(self, prime_lenght=100):
        self.pl = prime_lenght
        self.pari_keys_generator()

    @staticmethod
    def _gcd(a, b):
        """ Calculate the GCD between two numbers."""
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def _egcd(a, b):
        """Apply the Extended Euclidian Algorithm to two numbers."""
        if a == 0:
            return (b, 0, 1)
        g, y, x = RSA._egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    @staticmethod
    def _modinv(b, n):
        """Uses the Extended Euclidian Algorithm to calculate the value
        of b^-1 mod n.
        """
        g, x, _ = RSA._egcd(b, n)
        if g == 1:
            return x % n

    @staticmethod
    def _is_prime(n, iterations=40):
        """Tes of Miller-Rabin to determinate if a number is prime."""
        s, m = 0, n - 1
        if n in [1, 2]:
            return True
        if n % 2 == 0:
            return False
        while m % 2 == 0:
            m = m // 2
            s += 1
        for _ in range(iterations):
            a = random.randrange(2, n - 1)
            x = pow(a, m, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            return False
        return True

    @staticmethod
    def _prime_generator(k):
        """Generate a prime number of length k."""
        def set_bit(v, i, bit):
            """Change the i-th bit of v with 1 or 0"""
            mask = 1 << i
            v &= ~mask
            if bit == 1:
                v |= mask
            return v

        if k == 1:
            return random.choice([1, 2, 3, 5, 7])
        while True:
            b = random.getrandbits(334)
            b = set_bit(b, len(str(b))-1, 1)
            b = set_bit(b, 1, 1)
            if RSA._is_prime(b):
                return b

    @staticmethod
    def print_text(text):
        """Join element of a list and cast them to string."""
        return ''.join(str(t) for t in text)

    def pari_keys_generator(self):
        """Generate the private and public keys.

        Variables:
            - p and q are two prime numbers.
            - n is their product p*q.
            - phi is their totient (p-1) * (q-1).
            - e is a random integer between 1 and phi, coprime with the latter.
            - d is the modular inverse of e and phi.
        Returns:
            Set the private key as (d, n) and the public key as (e, n)
        """
        self.__p = RSA._prime_generator(self.pl)
        self.__q = RSA._prime_generator(self.pl)
        n = self.__p * self.__q
        # phi totient of n
        phi = (self.__p - 1) * (self.__q - 1)
        # find an e coprime with phi
        e = random.randrange(1, phi)
        while RSA._gcd(e, phi) != 1:
            e = random.randrange(1, phi)
        # d = e^-1 mod phi
        d = RSA._modinv(e, phi)
        self.__pub_key = (e, n)
        self.__priv_key = (d, n)

    def encrypt(self, plaintext):
        """Encrypt a text by calculating the value of m^k mod n
        for every letter m in the plaintext.

        Args:
            plaintext: the text to be encrypted.
        Return:
            A list of every letter encrypted.
        """
        k, n = self.__pub_key
        ct = [pow(ord(m), k, n) for m in plaintext]
        return ct

    def decrypt(self, ciphertext):
        """Decript a list of encrypted letters using c^k mod n
        for every number c in the list.

        Args:
            ciphertext: the list of numbers to be decrypted.
        Return:
            A decrypted plaintext.
        """
        k, n = self.__priv_key
        pt = [chr(pow(c, k, n)) for c in ciphertext]
        return RSA.print_text(pt)

    def crt_decrypt(self, ciphertext):
        """ RSA decryption using the Chinese Remainder Theorem. """
        k, n = self.__pub_key
        dp = RSA._modinv(k, self.__p - 1)
        dq = RSA._modinv(k, self.__q - 1)
        qinv = RSA._modinv(self.__q, self.__p)
        pt = []
        for c in ciphertext:
            m1 = pow(c, dp, self.__p)
            m2 = pow(c, dq, self.__q)
            h = (qinv * (m1 - m2)) % self.__p
            m = m2 + h * self.__q
            pt.append(chr(m))
        return RSA.print_text(pt)
