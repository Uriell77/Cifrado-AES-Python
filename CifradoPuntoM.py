# -*- coding: utf-8 -*-
"""
Created on Mon May 18 18:07:55 2020

@author: Luis Hermoso
Contactos: hermoso77@gmail.com
Telegram, Instagram: @Uriell77
"""

from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import hashlib

def pad_text(text, multiple):
    #Rellenado de texto
    #multiple es el limite de la cadena (16)
       extra_bytes = len(text) % multiple
       padding_size = multiple - extra_bytes
       padding = chr(padding_size) * padding_size
       padded_text = text + padding
       return padded_text


def ClaveCifrado(clave):
    #Convertir clave de cifrado a hash256 tomando los primeros 16 caracteres
    e = clave.encode('utf-8') #clave de cifrado
    a = hashlib.new('sha256', e)#convertir a sha256
    hash16 = a.digest()[:16] # se toman los primeros 16 caracteres
    #b64encode(hash16).decode('utf-8') solo para visualizar
    return  hash16 #Se usa como clave de cifrado para los datos de segundo factor y cvv


def cryp_aes(texto, hashs):
    #encripta texto usando el hash previamente generado en ClaveCifrado
    texto = pad_text(texto, 16)
    obj = AES.new(hashs, AES.MODE_ECB)
    res = obj.encrypt(texto)
    return b64encode(res).decode('utf-8')


def decrypto(enc, hashs):
    #Descifra dato encriptado previamente con cryp_aes y el hash generado en ClaveCifrado
    enc = b64decode(enc)
    decipher = AES.new(hashs, AES.MODE_ECB)
    res = decipher.decrypt(enc)
    return (res)

#Ejemplo:
#llave = ClaveCifrado('CLAVE_DE_CIFRADO')

#res = cryp_aes('TEXTO', llave)
#print('Cifrada: ', res)
    
#res = decrypto(CIFRADO, llave)
#print('Descifrada:', res)