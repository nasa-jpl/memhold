#!/usr/bin/env python3

import random
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--min', '-m', type=int, default=0x10000)
parser.add_argument('--max', '-M', type=int, default=0x70000)
parser.add_argument('--count', '-c', type=int, default=100)
parser.add_argument('--seed', '-s', type=int, default=42)

args = parser.parse_args()

ion_ranges = [
    (0x20000, 0x30000),
    (0x7f600, 0x7fc14),
    (0x05a00, 0x07b00),
    (0x08000, 0x0d000),
    (0x6e400, 0x6e408)
]

random.seed(args.seed)

for _ in range(args.count):
    r = None
    while r is None:
        r = random.randint(args.min,args.max)
        for ion_start, ion_end in ion_ranges:
            if r >= ion_start and r < ion_end:
                r = None
                break

    print(f'{random.randint(args.min,args.max):x}')

