import random
import time


class RSA:
    """RSA Scheme

    Args:
        prime_lenght: prime lenght used for the keys generations. 
            [default: 10^100]
    """

    def __init__(self, prime_lenght=100):
        self.pl = prime_lenght
        self.pari_keys_generator()

    # Greates Common Divisor
    @staticmethod
    def _gcd(a, b):
        assert a >= 0 and b >= 0, (
            "Both number must be positive integers")
        if b == 0:
            return b
        return RSA._gcd(b, a % b)

    # Extended Euclidian Algorithm
    @staticmethod
    def _egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = RSA._egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    # Miller-Rabin Primality Test
    @staticmethod
    def _is_prime(n, iterations=40):
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

    # Prime number generator
    @staticmethod
    def _prime_generator(k):
        while True:
            n = random.randrange(10**(k - 1), 10**k - 1, 1)
            if RSA._is_prime(n):
                return n

    def pari_keys_generator(self):
        s = time.time()
        p = RSA._prime_generator(self.pl)
        print('1 - %s' % (time.time() - s))
        q = RSA._prime_generator(self.pl)
        print('2 - %s' % (time.time() - s))
        n = p * q
        print('3 - %s' % (time.time() - s))
        # phi totient of n
        phi = (p - 1) * (q - 1)
        print('4 - %s' % (time.time() - s))
        # find an e coprime with phi
        e = random.randrange(1, phi)
        while RSA._gcd(e, phi) != 1:
            e = random.randrange(1, phi)
        print('5 - %s' % (time.time() - s))
        d = RSA._egcd(e, phi)[0]
        print('6 - %s' % time.time() - s)
        self.pub_key = (e, n)
        self.priv_key = (d, n)
