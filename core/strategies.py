from abc import ABC, abstractmethod
import itertools
import multiprocessing
import ctypes
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List, Generator, Tuple
import logging
from tqdm import tqdm

logger = logging.getLogger(__name__)

class CrackingStrategy(ABC):
    """Abstract base class for different cracking strategies"""
    
    @abstractmethod
    def execute(self, jwt_components, **kwargs) -> Optional[str]:
        """Execute the cracking strategy"""
        pass

    @staticmethod
    def create_verifier_for_process(jwt_components):
        """Create a new verifier instance for each process"""
        from core.verifiers import SignatureVerifier
        return SignatureVerifier.create(jwt_components)

def _brute_force_worker(args: Tuple[List[str], object, multiprocessing.Value]) -> Optional[str]:
    """Worker function for brute force strategy"""
    batch, jwt_components, found_flag = args
    try:
        verifier = CrackingStrategy.create_verifier_for_process(jwt_components)
        for candidate in batch:
            if found_flag.value:
                return None
            if verifier.verify(candidate):
                found_flag.value = True
                return candidate
        return None
    except Exception as e:
        logger.error(f"Error in worker process: {e}")
        return None

def _wordlist_worker(args: Tuple[int, int, str, object, multiprocessing.Value]) -> Optional[str]:
    """Worker function for wordlist strategy"""
    chunk_start, chunk_size, wordlist_path, jwt_components, found_flag = args
    try:
        verifier = CrackingStrategy.create_verifier_for_process(jwt_components)
        with open(wordlist_path, 'rb') as f:
            f.seek(chunk_start)
            chunk_data = f.read(chunk_size).decode('utf-8', errors='ignore')
            words = chunk_data.splitlines()

            for word in words:
                if found_flag.value:
                    return None
                if verifier.verify(word):
                    found_flag.value = True
                    return word
        return None
    except Exception as e:
        logger.error(f"Error in worker process: {e}")
        return None

class BruteForceStrategy(CrackingStrategy):
    """Optimized brute force cracking strategy"""
    
    def __init__(self, workers: int):
        self.workers = workers

    def _generate_combinations(self, charset: str, length: int, batch_size: int = 10000) -> Generator[List[str], None, None]:
        """Generate combinations in batches"""
        batch = []
        for combo in itertools.product(charset, repeat=length):
            if len(batch) >= batch_size:
                yield batch
                batch = []
            batch.append(''.join(combo))
        if batch:
            yield batch

    def execute(self, jwt_components, **kwargs) -> Optional[str]:
        charset = kwargs.get('charset', 'abcdefghijklmnopqrstuvwxyz')
        max_length = kwargs.get('max_length', 4)

        # Create a shared flag using a Manager
        with multiprocessing.Manager() as manager:
            found_flag = manager.Value(ctypes.c_bool, False)

            for length in range(1, max_length + 1):
                total_combinations = len(charset) ** length
                logger.info(f"Trying length {length} ({total_combinations:,} combinations)")

                with ProcessPoolExecutor(max_workers=self.workers) as executor:
                    futures = {}
                    batch_generator = self._generate_combinations(charset, length)

                    with tqdm(total=total_combinations, desc=f"Length {length}") as pbar:
                        try:
                            while True:
                                try:
                                    batch = next(batch_generator)
                                    if found_flag.value:
                                        break

                                    future = executor.submit(_brute_force_worker, (batch, jwt_components, found_flag))
                                    futures[future] = len(batch)
                                except StopIteration:
                                    break

                                # Process completed futures
                                for completed in list(as_completed(futures.keys())):
                                    result = completed.result()
                                    pbar.update(futures.pop(completed))
                                    if result:
                                        return result
                        except KeyboardInterrupt:
                            logger.info("\nInterrupted by user")
                            return None

        return None

class WordlistStrategy(CrackingStrategy):
    """Memory-efficient wordlist-based cracking strategy"""
    
    def __init__(self, workers: int):
        self.workers = workers

    def execute(self, jwt_components, **kwargs) -> Optional[str]:
        wordlist_path = kwargs.get('wordlist_path')
        if not wordlist_path:
            raise ValueError("Wordlist path is required")

        # Create a shared flag using a Manager
        with multiprocessing.Manager() as manager:
            found_flag = manager.Value(ctypes.c_bool, False)

            file_size = Path(wordlist_path).stat().st_size
            chunk_size = max(file_size // (self.workers * 4), 1024 * 1024)
            chunks = [(i, min(chunk_size, file_size - i)) 
                     for i in range(0, file_size, chunk_size)]

            with ProcessPoolExecutor(max_workers=self.workers) as executor:
                futures = [
                    executor.submit(_wordlist_worker, 
                                  (start, size, wordlist_path, jwt_components, found_flag))
                    for start, size in chunks
                ]

                with tqdm(total=len(chunks), desc="Processing chunks") as pbar:
                    try:
                        for future in as_completed(futures):
                            result = future.result()
                            pbar.update(1)
                            if result:
                                return result
                    except KeyboardInterrupt:
                        logger.info("\nInterrupted by user")
                        return None

            return None