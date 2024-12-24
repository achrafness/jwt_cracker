import argparse
import json
import sys
import logging
from core.components import JWTCracker
from core.strategies import BruteForceStrategy, WordlistStrategy
from utils.logging_config import configure_logging

logger = configure_logging()

def main():
    parser = argparse.ArgumentParser(description='High-Performance JWT Cracking Tool')
    parser.add_argument('token', help='JWT token to crack')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-c', '--charset', default='abcdefghijklmnopqrstuvwxyz',
                      help='Character set for brute force (default: lowercase letters)')
    parser.add_argument('-l', '--max-length', type=int, default=4,
                      help='Maximum length for brute force (default: 4)')
    parser.add_argument('-t', '--threads', type=int,
                      help='Number of worker processes (default: CPU count)')
    
    args = parser.parse_args()

    try:
        cracker = JWTCracker(args.token, args.threads)
        logger.info("\n=== JWT Token Information ===")
        logger.info(f"Algorithm: {cracker.components.algorithm}")
        logger.info(f"Header: {json.dumps(cracker.components.decoded_header, indent=2)}")
        logger.info(f"Payload: {json.dumps(cracker.components.decoded_payload, indent=2)}")

        if args.wordlist:
            strategy = WordlistStrategy(cracker.workers)
            cracker.crack(strategy, wordlist_path=args.wordlist)
        else:
            strategy = BruteForceStrategy(cracker.workers)
            cracker.crack(strategy, charset=args.charset, max_length=args.max_length)

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()