import base64
import hmac
import hashlib
import sys

def base64_url_decode(data):
    """Decodes a base64 URL-encoded string."""
    padding = '=' * (4 - (len(data) % 4)) 
    return base64.urlsafe_b64decode(data + padding)

def base64_url_encode(data):
    """Encodes data to a base64 URL-safe string."""
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def brute_force_jwt(jwt_token, wordlist):
    """
    Brute-force the secret key for a given JWT token.

    :param jwt_token: The JWT token to crack.
    :param wordlist: Path to the wordlist containing potential secret keys.
    """
    header, payload, signature = jwt_token.split('.')
    
    decoded_signature = base64_url_decode(signature)

    with open(wordlist, 'r') as f:
        for secret in f:
            secret = secret.strip()
            # Generate  HMAC256
            message = f"{header}.{payload}".encode()
            generated_signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            
            if generated_signature == decoded_signature:
                print(f"[+] Secret key found: {secret}")
                return

    print("[-] Secret key not found in the wordlist.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python jwt_bruteforce.py <jwt_token> <wordlist_path>")
        sys.exit(1)

    jwt_token = sys.argv[1]
    wordlist = sys.argv[2]

    brute_force_jwt(jwt_token, wordlist)