#!/usr/bin/env python

"""
Post-Quantum MsgToCypher.py - Compatible avec le pipeline SecCW

* ML-KEM-768 (Kyber) pour encapsulation de clés - NIST Level 3
* AES-256-GCM pour chiffrement symétrique avec authentification
* Format de sortie compatible avec CWToCS8.py
* Clés stockées en JSON pour faciliter le partage

Installation:
    pip install liboqs cryptography

Utilisation:
    # Générer une paire de clés (une seule fois)
    python MsgToCypher_PQ.py genkey
    
    # Chiffrer avec clés auto-générées
    python MsgToCypher_PQ.py test
    
    # Chiffrer avec clés existantes
    python MsgToCypher_PQ.py enc test 
    
    # Déchiffrer
    python MsgToCypher_PQ.py dec <ciphertext_hex>
"""

import secrets
import sys
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    import liboqs
    KEM_ALG = 'ML-KEM-768'  # NIST Level 3 - Post-quantum
except ImportError:
    print("[!] Erreur: liboqs non installé.")
    print("    Installez avec: pip install liboqs")
    print("    ou mettez à jour requirements.txt")
    sys.exit(1)


# Fichiers de clés par défaut
KEY_DIR = Path("./pq_keys")
PUBLIC_KEY_FILE = KEY_DIR / "public_key.json"
SECRET_KEY_FILE = KEY_DIR / "secret_key.json"


def init_keydir():
    """Crée le répertoire des clés s'il n'existe pas"""
    KEY_DIR.mkdir(exist_ok=True)


def generer_paire_cles():
    """
    Génère une paire de clés Kyber ML-KEM-768
    
    Returns:
        tuple: (public_key_bytes, secret_key_bytes)
    """
    print("[*] Génération de la paire de clés ML-KEM-768...")
    kemp = liboqs.KeyEncapsulation(KEM_ALG)
    public_key = kemp.generate_keypair()
    secret_key = kemp.export_secret_key()
    return public_key, secret_key


def sauvegarder_cles(public_key, secret_key):
    """
    Sauvegarde les clés en fichiers JSON sécurisés
    
    Args:
        public_key (bytes): Clé publique Kyber
        secret_key (bytes): Clé privée Kyber
    """
    init_keydir()
    
    # Sauvegarder la clé publique (peut être partagée)
    with open(PUBLIC_KEY_FILE, 'w') as f:
        json.dump({'public_key': public_key.hex().upper()}, f, indent=2)
    print(f"[+] Clé publique sauvegardée: {PUBLIC_KEY_FILE}")
    
    # Sauvegarder la clé privée (attention: sécurité)
    with open(SECRET_KEY_FILE, 'w') as f:
        json.dump({'secret_key': secret_key.hex().upper()}, f, indent=2)
    # Permissions restrictives (lecture seule pour le propriétaire)
    os.chmod(SECRET_KEY_FILE, 0o600)
    print(f"[+] Clé privée sauvegardée: {SECRET_KEY_FILE} (permissions: 600)")


def charger_cles():
    """
    Charge les clés depuis les fichiers JSON
    
    Returns:
        tuple: (public_key_bytes, secret_key_bytes)
        
    Raises:
        SystemExit: Si les clés n'existent pas
    """
    try:
        with open(PUBLIC_KEY_FILE, 'r') as f:
            pub_data = json.load(f)
        with open(SECRET_KEY_FILE, 'r') as f:
            sec_data = json.load(f)
        
        public_key = bytes.fromhex(pub_data['public_key'])
        secret_key = bytes.fromhex(sec_data['secret_key'])
        return public_key, secret_key
    except FileNotFoundError:
        print("[!] Erreur: Clés non trouvées.")
        print("    Générez-les avec: python MsgToCypher_PQ.py genkey")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[!] Erreur: Format de clé invalide.")
        sys.exit(1)


def format_sortie(kem_ct, nonce, aes_ct, tag):
    """
    Formate les données chiffrées pour le pipeline
    
    Structure: [KEM_ciphertext(1088)][nonce(12)][AES_ciphertext(variable)][tag(16)]
    
    Args:
        kem_ct (bytes): Ciphertext Kyber (1088 bytes)
        nonce (bytes): Nonce AES-GCM (12 bytes)
        aes_ct (bytes): Ciphertext AES (taille variable)
        tag (bytes): Authentification tag (16 bytes)
        
    Returns:
        bytes: Données binaires concaténées
    """
    donnees = kem_ct + nonce + aes_ct + tag
    return donnees


def parser_donnees(donnees_bin):
    """
    Parse les données chiffrées selon le format
    
    Args:
        donnees_bin (bytes): Données à parser
        
    Returns:
        tuple: (kem_ct, nonce, aes_ct, tag)
        
    Raises:
        ValueError: Si le format est invalide
    """
    # Tailles fixes pour ML-KEM-768
    KEM_CT_SIZE = 1088  # Kyber 768 ciphertext size
    NONCE_SIZE = 12      # 96 bits pour GCM
    TAG_SIZE = 16        # 128 bits pour GCM
    
    if len(donnees_bin) < KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError(
            f"Données chiffrées invalides (trop courtes): "
            f"{len(donnees_bin)} bytes au lieu de min "
            f"{KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE}"
        )
    
    kem_ct = donnees_bin[:KEM_CT_SIZE]
    nonce = donnees_bin[KEM_CT_SIZE:KEM_CT_SIZE+NONCE_SIZE]
    tag = donnees_bin[-TAG_SIZE:]
    aes_ct = donnees_bin[KEM_CT_SIZE+NONCE_SIZE:-TAG_SIZE]
    
    return kem_ct, nonce, aes_ct, tag


def chiffre_message(cle_publique, message):
    """
    Chiffre un message avec Kyber + AES-256-GCM
    
    Processus:
    1. Kyber encapsule un secret partagé
    2. AES-256-GCM chiffre le message avec ce secret
    3. Retour en format hex compatible pipeline
    
    Args:
        cle_publique (bytes): Clé publique Kyber
        message (str): Message à chiffrer
        
    Returns:
        str: Ciphertext en hexadécimal
    """
    # Encapsulation Kyber - génère un secret et son KEM ciphertext
    kemp = liboqs.KeyEncapsulation(KEM_ALG, public_key=cle_publique)
    kem_ct, shared_secret = kemp.encap_secret()
    
    # Dérivation de la clé symétrique (32 bytes pour AES-256)
    cle_sym = shared_secret[:32]
    nonce = secrets.token_bytes(12)  # 96 bits pour GCM
    
    # Chiffrement AES-256-GCM du message
    message_bytes = message.encode('utf-8')
    cipher = Cipher(
        algorithms.AES(cle_sym),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    aes_ct = encryptor.update(message_bytes) + encryptor.finalize()
    tag = encryptor.tag  # Authentication tag
    
    # Format binaire compatible pipeline
    donnees_bin = format_sortie(kem_ct, nonce, aes_ct, tag)
    return donnees_bin.hex().upper()


def dechiffre_message(cle_privee, donnees_hex):
    """
    Déchiffre un message avec Kyber + AES-256-GCM
    
    Processus:
    1. Kyber décapsule le secret partagé
    2. AES-256-GCM déchiffre le message
    3. Vérification de l'authentification
    
    Args:
        cle_privee (bytes): Clé privée Kyber
        donnees_hex (str): Ciphertext en hexadécimal
        
    Returns:
        str: Message en clair
        
    Raises:
        ValueError: Si les données sont invalides
        cryptography.exceptions.InvalidTag: Si l'authentification échoue
    """
    donnees_bin = bytes.fromhex(donnees_hex)
    kem_ct, nonce, aes_ct, tag = parser_donnees(donnees_bin)
    
    # Décapsulation Kyber - récupère le secret partagé
    kemp = liboqs.KeyEncapsulation(KEM_ALG, secret_key=cle_privee)
    shared_secret = kemp.decap_secret(kem_ct)
    
    # Dérivation de la clé symétrique (identique à l'encryption)
    cle_sym = shared_secret[:32]
    
    # Déchiffrement AES-256-GCM avec vérification d'authentification
    cipher = Cipher(
        algorithms.AES(cle_sym),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    message = decryptor.update(aes_ct) + decryptor.finalize()
    
    return message.decode('utf-8')


def afficher_usage():
    """Affiche l'aide d'utilisation"""
    print("Usage: python MsgToCypher_PQ.py <command> [args]")
    print("\nCommandes:")
    print("  genkey                           Générer une paire de clés")
    print("  <message>                        Chiffrer (auto-génère si nécessaire)")
    print("  enc <message>                    Chiffrer avec clés existantes")
    print("  dec <ciphertext_hex>             Déchiffrer")
    print("\nExemples:")
    print("  python MsgToCypher_PQ.py genkey")
    print("  python MsgToCypher_PQ.py 'test'")
    print("  python MsgToCypher_PQ.py enc 'test'")
    print("  python MsgToCypher_PQ.py dec EFAADCF7EA0A786EF7B4EF75...")


def main():
    """Fonction principale - traite les arguments et appelle les fonction appropriées"""
    
    if len(sys.argv) < 2:
        afficher_usage()
        sys.exit(0)

    command = sys.argv[1]

    # ========== GENKEY: Générer une nouvelle paire de clés ==========
    if command == "genkey":
        public_key, secret_key = generer_paire_cles()
        sauvegarder_cles(public_key, secret_key)
        print(f"\n[✓] Clés générées et sauvegardées avec succès")
        print(f"    Répertoire: {KEY_DIR}")
        return

    # ========== Chiffrement automatique ==========
    if len(sys.argv) == 2 and command not in ['enc', 'dec']:
        message = command
        
        # Vérifier si les clés existent, sinon les générer
        if not PUBLIC_KEY_FILE.exists():
            print("[*] Clés non trouvées, génération automatique...")
            public_key, secret_key = generer_paire_cles()
            sauvegarder_cles(public_key, secret_key)
        else:
            public_key, _ = charger_cles()
        
        # Chiffrement
        print(f"\n[*] Chiffrement du message: '{message}'")
        ct = chiffre_message(public_key, message)
        
        print(f"[+] key: {public_key.hex().upper()[:64]}... ({len(public_key)} bytes)")
        print(f"[+] cipherText: {ct}")
        
        # Afficher les prochains nonces pour le pipeline CW
        print(f"\n[*] Prochains nonces générés (optionnel):")
        for i in range(4):
            print(f"    next nonce: {secrets.token_bytes(12).hex().upper()}")
        
        # Vérification du déchiffrement
        print(f"\n[*] Verification du déchiffrement...")
        _, secret_key = charger_cles()
        msg_dec = dechiffre_message(secret_key, ct)
        if msg_dec == message:
            print(f"[✓] Message vérifié: '{msg_dec}'")
        else:
            print(f"[!] Erreur: Le message déchiffré ne correspond pas")
            sys.exit(1)
        return

    # ========== Chiffrement avec clés existantes ==========
    if command == 'enc' and len(sys.argv) == 3:
        message = sys.argv[2]
        public_key, _ = charger_cles()
        
        print(f"[*] Chiffrement: '{message}'")
        ct = chiffre_message(public_key, message)
        
        print(f"[+] key: {public_key.hex().upper()[:64]}... ({len(public_key)} bytes)")
        print(f"[+] cipherText: {ct}")
        return

    # ========== Déchiffrement ==========
    if command == 'dec' and len(sys.argv) == 3:
        ciphertext_hex = sys.argv[2]
        _, secret_key = charger_cles()
        
        try:
            print(f"[*] Déchiffrement...")
            message = dechiffre_message(secret_key, ciphertext_hex)
            print(f"[+] message: {message}")
        except ValueError as e:
            print(f"[-] Erreur: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Erreur de déchiffrement (authentification échouée?): {e}")
            sys.exit(1)
        return

    # ========== Commande invalide ==========
    print(f"[-] Commande invalide: {command}")
    afficher_usage()
    sys.exit(1)


if __name__ == "__main__":
    main()
