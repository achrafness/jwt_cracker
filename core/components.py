from __future__ import annotations
import base64
import json
import sys
import time
import signal
import multiprocessing
import logging
from dataclasses import dataclass
from typing import Optional, Dict

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class JWTComponents:
    """Immutable data class for JWT components"""
    header: str
    payload: str
    signature: str
    algorithm: str
    decoded_header: dict
    decoded_payload: dict

class JWTCracker:
    """High-performance JWT cracking orchestrator"""
    
    def __init__(self, token: str, workers: int = None):
        self.token = token
        self.workers = workers or multiprocessing.cpu_count()
        self.components = self._parse_token(token)
        signal.signal(signal.SIGINT, self._handle_interrupt)
        
    def _handle_interrupt(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        logger.info("\nInterrupting... Cleaning up...")
        sys.exit(0)

    @staticmethod
    def _parse_token(token: str) -> JWTComponents:
        """Parse and validate JWT token"""
        try:
            header, payload, signature = token.split('.')
            padding = '=' * (-len(header) % 4)
            decoded_header = json.loads(base64.urlsafe_b64decode(header + padding))
            padding = '=' * (-len(payload) % 4)
            decoded_payload = json.loads(base64.urlsafe_b64decode(payload + padding))
            
            return JWTComponents(
                header=header,
                payload=payload,
                signature=signature,
                algorithm=decoded_header.get('alg', 'HS256'),
                decoded_header=decoded_header,
                decoded_payload=decoded_payload
            )
        except Exception as e:
            raise ValueError(f"Invalid JWT format: {str(e)}")

    def crack(self, strategy, **kwargs) -> Optional[str]:
        """Execute cracking strategy with performance monitoring"""
        start_time = time.time()
        try:
            result = strategy.execute(self.components, **kwargs)
            elapsed = time.time() - start_time
            
            if result:
                logger.info(f"\n[+] Success! Secret found: {result}")
            else:
                logger.info("\n[-] No valid secret found")
            
            logger.info(f"Time taken: {elapsed:.2f} seconds")
            return result
            
        except KeyboardInterrupt:
            logger.info("\nOperation cancelled by user")
            return None
        except Exception as e:
            logger.error(f"Error during cracking: {str(e)}")
            return None