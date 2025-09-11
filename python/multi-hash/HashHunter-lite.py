import hashlib
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, bcrypt
from Crypto.Hash import RIPEMD

def compute_hashes(file_path):
    hashes = {}

    # Lectura del archivo en binario
    with open(file_path, "rb") as f:
        data = f.read()

    # Hashes básicos (hashlib)
    hashes["MD5"] = hashlib.md5(data).hexdigest()
    hashes["SHA1"] = hashlib.sha1(data).hexdigest()
    hashes["SHA224"] = hashlib.sha224(data).hexdigest()
    hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    hashes["SHA384"] = hashlib.sha384(data).hexdigest()
    hashes["SHA512"] = hashlib.sha512(data).hexdigest()
    hashes["SHA3-256"] = hashlib.sha3_256(data).hexdigest()
    hashes["SHA3-512"] = hashlib.sha3_512(data).hexdigest()
    hashes["BLAKE2b"] = hashlib.blake2b(data).hexdigest()
    hashes["BLAKE2s"] = hashlib.blake2s(data).hexdigest()

    # Hash adicional (PyCryptodome)
    hashes["RIPEMD160"] = RIPEMD.new(data).hexdigest()

    # Variantes crypt (Passlib)
    hashes["MD5-Crypt"] = md5_crypt.hash(data)
    hashes["SHA256-Crypt"] = sha256_crypt.hash(data)
    hashes["SHA512-Crypt"] = sha512_crypt.hash(data)
    hashes["Bcrypt"] = bcrypt.hash(data)

    return hashes

if __name__ == "__main__":
    path = input("Ruta del archivo: ").strip()
    results = compute_hashes(path)

    print("\n=== Resultados de hashes ===\n")
    for algo, value in results.items():
        print(f"{algo}: {value}")

    # Guardar en archivo
    with open("hashes_resultados.txt", "w") as f:
        for algo, value in results.items():
            f.write(f"{algo}: {value}\n")

    print("\nGuardado en hashes_resultados.txt")
