#Created by: Bartosz Tobiński

from Crypto.PublicKey import RSA
import random
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from colorama import Fore

#############################################################################

def generateRSAKeys(randomFile, keySize=2048):
    with open(randomFile, 'rb') as file:
        randomSeed = file.read()

    def randfunc(n):
        start = random.randint(0, len(randomSeed) - n - 1)  #randomowy index poczatkowy
        return randomSeed[start:start + n]
    
    key = RSA.generate(keySize, randfunc=randfunc)
    return key, key.publickey()


def saveKeyToFile(key, filePath):
    with open(filePath, 'wb') as file:
        file.write(key.export_key())


def loadKeyFromFile(filePath):
    with open(filePath, 'rb') as file:
        key = RSA.import_key(file.read())
    return key


def generateSignature(privateKey, filePath):
    try:
        with open(filePath, 'rb') as file:
            randomSeed = file.read()
    except:
        print(Fore.RED + "Nie znaleziono pliku  \n")
        return False
    hash = SHA256.new(randomSeed)
    signature = pkcs1_15.new(privateKey).sign(hash)
    return signature


def verifySignature(publicKey, filePath, signature):
    try: 
        with open(filePath, 'rb') as file:
            message = file.read()
            
    except:
        print(Fore.RED + "Nie znaleziono pliku  \n")
        return
    try:
        h = SHA256.new(message)
        pkcs1_15.new(publicKey).verify(h, signature)
        return True
    except:
        return False

##########################################################################

while(True):  
    print(Fore.WHITE + "Co chcesz zrobić? \n 1. Podpisz plik \n 2. Sprawdź autentyczność podpisu pliku na podstawie klucza publicznego \n 3. Wyjdź z programu \n")
    choice = input()  

    if(choice == "1"):
        privateKey, publicKey = generateRSAKeys("../generator/output.txt") #tutaj plik z randomowymi wartosciami wygenerowanymi z poprzedniego zadania
        saveKeyToFile(privateKey, "private_key.pem")
        saveKeyToFile(publicKey, "public_key.pem")

        print("Podaj ścieżkę pliku do podpisu: ")
        filePath = input()

        signature = generateSignature(privateKey, filePath)

        print("Podaj ścieżkę do którego pliku wygenerować podpis: ")
        signatureFilePath = input()

        with open(signatureFilePath, 'x') as sigFile:
            sigFile.write(signature.hex());

        if(signature): 
            print(Fore.YELLOW + "Podpisano plik \n")
        else:
            continue

    elif(choice == "2"):
        print("Podaj ścieżkę pliku do sprawdzenia podpisu: ")
        filePath = input()

        print("Podaj ścieżkę klucza: ")
        pubKeyFilePath = input()

        signature = None

        print("Podaj ścieżkę pliku z podpisem: ")
        signatureFilePath = input()

        try:
            with open(signatureFilePath) as sigFile:
                signature = sigFile.read();
        except:
            signature = None

        try:
            publicKey = loadKeyFromFile(pubKeyFilePath)
            signature = bytes.fromhex(signature)
            isAuthentic = verifySignature(publicKey, filePath, signature)
        except: 
            print(Fore.RED + "Nie znaleziono któregoś z plików \n")
            continue
        

        if isAuthentic:
            print(Fore.GREEN + "Podpis jest autentyczny \n")
        else:
            print(Fore.RED + "Podpis nie jest autentyczny \n")

    else:
        break