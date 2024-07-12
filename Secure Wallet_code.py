from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import hashlib
import base64
import random
import json

class SecureWallet:
    def __init__(self, key):
        self.key = key
        self.balance = 0

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, ciphertext):
        data = base64.b64decode(ciphertext.encode('utf-8'))
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')

    def deposit(self, amount):
        self.balance += amount
        print(f"Setoran berhasil! Saldo saat ini: {self.balance}")

    def withdraw(self, amount):
        if amount <= self.balance:
            self.balance -= amount
            print(f"Penarikan berhasil! Saldo saat ini: {self.balance}")
        else:
            print("Dana tidak cukup untuk penarikan.")

    def check_balance(self):
        print(f"Saldo saat ini: {self.balance}")

    def save_wallet(self, filename='secure_wallet.dat'):
        wallet_data = {'balance': self.balance}
        encrypted_data = self.encrypt(json.dumps(wallet_data))

        with open(filename, 'w') as file:
            file.write(encrypted_data)
        print("Data Wallet berhasil disimpan dengan aman!")

    def load_wallet(self, filename='secure_wallet.dat'):
        try:
            with open(filename, 'r') as file:
                encrypted_data = file.read()
            decrypted_data = self.decrypt(encrypted_data)

            wallet_data = json.loads(decrypted_data)
            self.balance = wallet_data['balance']
            print("Wallet berhasil dimuat!")
        except FileNotFoundError:
            print("Tidak ada file Wallet yang ditemukan!")

# Fungsi untuk menghitung GCD (Greatest Common Divisor)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Fungsi untuk menghitung nilai e
def calculate_e(phi):
    e = 2
    while gcd(e, phi) != 1:
        e += 1
    return e

# Fungsi untuk menghitung nilai d (kunci privat)
def calculate_d(e, phi):
    k = 1
    while True:
        d = (k * phi + 1) / e
        if d.is_integer():
            return int(d)
        k += 1

# Fungsi untuk mengecek bilangan prima atau tidak
def isPrime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

# Fungsi untuk hashing pesan
def hash(plain_text, public_key):
    e, n = public_key
    digest_text = [pow(int.from_bytes(hashlib.sha256(char.encode()).digest(), 'big'), e, n) for char in plain_text]
    return digest_text

def randomPrime():
    minPrime = 0
    maxPrime = 1000
    cached_primes = [i for i in range(minPrime, maxPrime) if isPrime(i)]
    return random.choice([i for i in cached_primes])

def publicKeyMaker(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = calculate_e(phi)
    return e, n

def privateKeyMaker(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = calculate_e(phi)
    d = calculate_d(e, phi)
    return d, n

def autentikasiPengguna(a):
    while True:
      print()
      input_passwd = input("Masukkan password anda: ")
      input_passwd_digest = hash(input_passwd, public_key)
      if input_passwd_digest == a:
        return print("Login berhasil!")
        break

      else:
        print("Password salah! Silahkan coba lagi!")

def autentikasiPin(b):
    while True:
      print()
      input_pin = input("Masukkan PIN anda: ")
      input_pin_digest = hash(input_pin, public_key)
      if input_pin_digest == b:
        break

      else:
        print("PIN salah! Silahkan coba lagi!")

# Fungsi utama
if __name__ == "__main__":
    # Men-generate bilangan prima random untuk p dan q
    p = randomPrime()
    q = randomPrime()

    # Membuat public key dan private key
    public_key = publicKeyMaker(p, q)
    private_key = privateKeyMaker(p, q)

    print("Selamat datang di aplikasi Secure Wallet")
    print()
    print("Silahkan membuat akun terlebih dahulu")
    usrname = input("Masukkan username yang anda hendaki: ")
    passwd = input("Masukkan password yang anda hendaki: ")
    pin  = input("Masukkan PIN yang anda hendaki: ")

    # Hashing password
    passwd_digest = hash(passwd, public_key)
    print("Hasil hashing password:", passwd_digest)

    # Hashing PIN
    pin_digest = hash(pin, public_key)
    print("Hasil hashing pin:", pin_digest)

    autentikasiPengguna(passwd_digest)

    # Inisialisasi saldo
    saldo = 0

    key_input = get_random_bytes(16)
    wallet = SecureWallet(key_input)
    while True:
        print("\nSecure Wallet Menu:")
        print("1. Setor Uang")
        print("2. Ambil Uang")
        print("3. Cek Saldo")
        print("4. Simpan Data Wallet")
        print("5. Memuat Data Wallet")
        print("6. Keluar")

        choice = input("Masukkan pilihan anda (1-6): ")

        if choice == '1':
            autentikasiPin(pin_digest)
            amount = float(input("Masukkan jumlah yang ingin disetor: "))
            wallet.deposit(amount)
        elif choice == '2':
            amount = float(input("Masukkan jumlah penarikan: "))
            autentikasiPin(pin_digest)
            wallet.withdraw(amount)
        elif choice == '3':
            wallet.check_balance()
        elif choice == '4':
            autentikasiPin(pin_digest)
            wallet.save_wallet()
        elif choice == '5':
            wallet.load_wallet()
        elif choice == '6':
            print("Terima kasih telah menggunakan Secure Wallet. Sampai jumpa!")
            break
        else:
            print("Pilihan tidak valid. Silahkan coba lagi.")