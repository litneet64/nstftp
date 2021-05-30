#!/usr/bin/env python3

import string
import itertools
import sys
import random

#BASE = "NSTFTP-client-go-{}"
BASE = "{}"

# check correct num of args
def check_args():
    if len(sys.argv) != 2:
        print(f"[+] Usage: {sys.argv[0]} <num of sols to print>")
        exit(127)

    return int(sys.argv[1])


# check that sum of chars in string is equal to 0x80 - 4 (124)
def check_sum(client_name):
    if (sum(client_name.encode()) % 256) == 124:
        return True
    return False


# check chars are between valid range
def check_valid_chars(client_name):
    for c in client_name:
        if (ord(c) - 0x21) > 0x59:
            return False

    return True


# validate a client name with previous functions
def check_client_name(cname):
    if check_valid_chars(cname) and check_sum(cname):
        return True
    return False


# bruteforce every comb of 5 chars for the client name
def main(n_sol):
    # get printable chars and shuffle order to get new solutions
    p_chars = list(string.printable)
    random.shuffle(p_chars)
    sol_c = 1

    for prod_tup in itertools.product(p_chars, repeat=5):
        client_name = BASE.format("".join(prod_tup))

        if sol_c == n_sol:
            return

        if check_client_name(client_name):
            print(f"[+] Working sol: {client_name.encode()}")
            sol_c += 1

    return


if __name__ == "__main__":
    n_sol = check_args()
    main(n_sol)
