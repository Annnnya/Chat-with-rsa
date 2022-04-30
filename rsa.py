"""
module with implementation of rsa algorithm and hash ebaluation
"""

import random
from math import sqrt
from hashlib import sha256

class RSA:
    """
    class with everything
    """
    def __init__(self) -> None:
        """
        generates public keys and private key
        """
        self.open_key()
        self.euclidian_algorithm()
    def share_public_key(self):
        """returns public key"""
        return self.public_key
    def gen_two_primes(self):
        """generates two big random primes"""
        prime = False
        while not prime:
            first = random.randint(100000, 99999999)

            prime = self.is_prime(first)

        prime = False
        while not prime:
            second = random.randint(100000, 9999999)
            prime = self.is_prime(second)
        return first,second

    def is_prime(self, num):
        """check if generated number is prime"""
        check_range=int(sqrt(num))+1
        if num%2==0:
            return False
        for i in range (3, check_range, 2):
            if num%i==0:
                return False
        return True

    def open_key(self):
        """generates open (public) key"""
        self.p, self.q = self.gen_two_primes()
        self.n =self.p*self.q
        self.f=(self.p-1)*(self.q-1)
        self.e = 65537
        self.is_prime(self.e)
        if self.f%self.e == 0:
            prime = False
            while not prime or self.f%self.e == 0:
                self.e+=1
                prime=self.is_prime(self.e)
        self.public_key = (self.e, self.n)

    def euclidian_algorithm(self):
        """evaluates scret key
        ed = 1 mod f, d-?"""
        a=self.f
        b=self.e
        acoe1, acoe2 = 0, 1
        bcoe1, bcoe2 = 1, 0
        while b > 0:
            cila = a//b
            ost = a%b
            acoe = acoe2 - cila * acoe1
            bcoe = bcoe2 - cila * bcoe1
            a=b
            b=ost
            acoe2, acoe1 = acoe1, acoe
            bcoe2, bcoe1 = bcoe1, bcoe
        if bcoe2 < 0:
            bcoe2 = self.f+bcoe2
        self.secret_key = (bcoe2, self.n)

    def str_to_num(self, message):
        """converts message to sequence of numbers"""
        numbers=[]
        res = []
        for i in message:
            numbers.append(str(ord(i)).zfill(4))
        if len(message)%2==0:
            for i in range(0, len(message), 2):
                res.append(int(numbers[i]+numbers[i+1]))
        else:
            for i in range(0, len(message)-1, 2):
                res.append(int(numbers[i]+numbers[i+1]))
            res.append(int(numbers[-1]+'0000'))
        # print(res)
        return res

    def num_to_str(self, nums):
        """converts sequence of numbers to str"""
        res=''
        for i in nums[:-1]:
            second=i%10000
            first=i//10000
            res+=chr(first)+chr(second)
        second=nums[-1]%10000
        first=nums[-1]//10000
        if second==0000:
            res+=chr(first)
        else:
            res+=chr(first)+chr(second)
        return res
    
    def encode(self, message:str, public_key:tuple):
        """encodes message with given publick key"""
        message = self.str_to_num(message)
        encifered_mesage=[]
        for i in message:
            by_mod=self.exponentiation(i, public_key[0], public_key[1])
            encifered_mesage.append(str(by_mod).zfill(len(str(public_key[1]))))
        return ''.join(encifered_mesage)
    
    def decode(self, encifered_mesage, secret_key=None):
        """decodes encrypted message with privete key"""
        if secret_key is None:
            secret_key=self.secret_key
        decoder = lambda x: self.exponentiation(x, secret_key[0], secret_key[1])
        lenn= len(str(self.n))
        nums = [decoder(int(encifered_mesage[i:i+lenn])) for i in range(0, len(encifered_mesage), lenn)]
        return self.num_to_str(nums)

    def exponentiation(self, bas, exp, module):
        """effcient function for power under module
        makes program work much faster"""
        if exp == 0:
            return 1
        if exp == 1:
            return bas % module
        mult = self.exponentiation(bas, int(exp / 2), module)
        mult = (mult * mult) % module
        if exp%2==0:
            return mult
        else:
            return ((bas%module)*mult)%module

    def eveluate_hash(self, message):
        """evaluates hash for string message"""
        return sha256(message.encode('utf-8')).hexdigest()    

# r =RSA()
# print(r.eveluate_hash('cd hgauli;hg long akgn\'ggnkj.a///'))
