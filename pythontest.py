#!/usr/bin/env python3

import textwrap
import argparse

long_text = 'WARNING: this is a very long text which I hope I could make use of textwrap module to wrap it against a reasonable length. still typing to make this sentence a little longer. still typing to add some argument here: %s' % 'THIS IS ARGUMENT'
print('\n\t'.join(textwrap.wrap(long_text)))

parser = argparse.ArgumentParser(description="My Parser")
parser.add_argument('-j', '--num-processes', dest='processes', action='store',
                    type=int, help='number of processes')

args = parser.parse_args()
print(args)
