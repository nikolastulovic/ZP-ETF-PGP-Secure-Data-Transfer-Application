import random

import frontend
import rings
from algorithms import zipAlg, radix64

if __name__ == '__main__':
    rings.read_from_files()

    try:
        frontend.main()
    finally:
        rings.save_to_files()