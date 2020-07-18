#!/usr/bin/env python3
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
gperf C file post-processor

We use gperf to build up a perfect hashtable of pointer values. The way gperf
does this is to create a table 'wordlist' indexed by a string representation
of a pointer address, and then doing memcmp() on a string passed in for
comparison

We are exclusively working with 4-byte pointer values. This script adjusts
the generated code so that we work with pointers directly and not strings.
This saves a considerable amount of space.
"""

import sys
import argparse
import os
import re
from distutils.version import LooseVersion
import elftools
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

if LooseVersion(elftools.__version__) < LooseVersion('0.24'):
    sys.exit("pyelftools is out of date, need version 0.24 or later")

# --- debug stuff ---

def debug(text):
    if not args.verbose:
        return
    sys.stdout.write(os.path.basename(sys.argv[0]) + ": " + text + "\n")


def error(text):
    sys.exit(os.path.basename(sys.argv[0]) + " ERROR: " + text)


def warn(text):
    sys.stdout.write(
        os.path.basename(
            sys.argv[0]) +
        " WARNING: " +
        text +
        "\n")


def reformat_str(match_obj):
    addr_str = match_obj.group(0)

    # Nip quotes
    addr_str = addr_str[1:-1]
    addr_vals = [0, 0, 0, 0, 0, 0, 0 , 0]
    ctr = 7
    i = 0

    while True:
        if i >= len(addr_str):
            break

        if addr_str[i] == "\\":
            if addr_str[i + 1].isdigit():
                # Octal escape sequence
                val_str = addr_str[i + 1:i + 4]
                addr_vals[ctr] = int(val_str, 8)
                i += 4
            else:
                # Char value that had to be escaped by C string rules
                addr_vals[ctr] = ord(addr_str[i + 1])
                i += 2

        else:
            addr_vals[ctr] = ord(addr_str[i])
            i += 1

        ctr -= 1

    return "(char *)0x%02x%02x%02x%02x%02x%02x%02x%02x" % tuple(addr_vals)


def process_line(line, fp):
    if line.startswith("#"):
        fp.write(line)
        return

    # Set the lookup function to static inline so it gets rolled into
    # z_object_find(), nothing else will use it
    if re.search(args.pattern + " [*]$", line):
        fp.write("static inline " + line)
        return

    m = re.search("gperf version (.*) [*][/]$", line)
    if m:
        v = LooseVersion(m.groups()[0])
        v_lo = LooseVersion("3.0")
        v_hi = LooseVersion("3.1")
        if (v < v_lo or v > v_hi):
            warn("gperf %s is not tested, versions %s through %s supported" %
                 (v, v_lo, v_hi))

    # Replace length lookups with constant len since we're always
    # looking at pointers
    line = re.sub(r'lengthtable\[key\]', r'sizeof(void *)', line)

    # Empty wordlist entries to have NULLs instead of ""
    line = re.sub(r'[{]["]["][}]', r'{}', line)

    # Suppress a compiler warning since this table is no longer necessary
    line = re.sub(r'static unsigned char lengthtable',
                  r'static unsigned char __unused lengthtable', line)

    # drop all use of register keyword, let compiler figure that out,
    # we have to do this since we change stuff to take the address of some
    # parameters
    line = re.sub(r'register', r'', line)

    # Hashing the address of the string
    line = re.sub(r"hash [(]str, len[)]",
                  r"my_hash(str, len)", line)

    # Just compare pointers directly instead of using memcmp
    if re.search("if [(][*]str", line):
        fp.write("            if (str == s)\n")
        return

    # Take the strings with the binary information for the pointer values,
    # and just turn them into pointers
    line = re.sub(r'["].*["]', reformat_str, line)

    fp.write(line)

def get_symbols(elf):
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            return {sym.name: sym.entry.st_value
                    for sym in section.iter_symbols()}

    raise LookupError("Could not find symbol table")

def parse_args():
    global args

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-i", "--input", required=True,
                        help="Input C file from gperf")
    parser.add_argument("-o", "--output", required=True,
                        help="Output C file with processing done")
    parser.add_argument("-p", "--pattern", required=True,
            help="Search pattern for objects")
    parser.add_argument("-k", "--kernel", required=True,
                        help="Input zephyr ELF binary")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print extra debugging information")
    args = parser.parse_args()
    if "VERBOSE" in os.environ:
        args.verbose = 1

gperf_extra_header = """
#include <init.h>
extern char z_object_data_end[];
#define DELTA (((const char *)(&z_object_data_end)) - ((const char *)OLD_DATA))

static unsigned int hash ( const char *str,  size_t len);

static unsigned int my_hash( const char *str,  size_t len)
{
    const char *adjusted = str - DELTA;

    printk("object %p adjusted %p\\n", str, adjusted);

    return hash((const char *)&adjusted, len);

}
"""

gperf_extra_footer = """

static void fixup_func(struct z_object *ko, void *ctx_ptr)
{
    void *old_addr = ko->name;
    ko->name = (uint8_t *)(ko->name) + DELTA;

    printk("%p -> %p\\n", old_addr, ko->name);
}

static int gperf_fixup(struct device *unused)
{
    z_object_gperf_wordlist_foreach(fixup_func, NULL);
    return 0;
}

SYS_INIT(gperf_fixup, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
"""

def main():
    parse_args()

    elf = ELFFile(open(args.kernel, "rb"))
    syms = get_symbols(elf)

    # Address of __data_ram_start in the prebuilt image, which didn't have
    # its memory addresses disturbed by the gperf data itself.
    # We use this and the final address of __data_ram_start to compute an
    # offset.
    old_data_begin = syms["z_object_data_end"]

    with open(args.input, "r") as in_fp, open(args.output, "w") as out_fp:
        out_fp.write("#define OLD_DATA 0x%x\n" % old_data_begin)
        out_fp.write(gperf_extra_header)
        for line in in_fp.readlines():
            process_line(line, out_fp)
        out_fp.write(gperf_extra_footer)


if __name__ == "__main__":
    main()
