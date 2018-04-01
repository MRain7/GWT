#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division
import os
import logging
import archinfo
import binascii
import re
from lib import classifier

input_dir = 'fragment/'
output_dir = 'detail/'
input_file = "fragment/heap_test.txt"
output_file = "detail/heap_test.txt"
pin_dir = 'pin/'

# clobber pattern
pattern1 = re.compile('.*(add|sub|and|xor|pop|mov|lea)\s+(?P<reg>\w+)(,|$)')
pattern2 = re.compile('.*(?P<opcode>enter|leave)(\s+\d|$)')
# pattern3 = re.compile('.*(call|ret|rep ret|int|jmp)\s+(?P<reg>\w+)(,|$)')

# limit of clobbered registers
NOP_LIMIT = 4

inputs = os.listdir(input_dir)
for filename in inputs:
    input_file = input_dir + filename
    output_file = output_dir + filename
    pin_file = pin_dir + filename
    print input_file + ' -> ' + output_file + ' & ' + pin_file
    output = open(output_file, 'w')
    pin = open(pin_file, 'w')

    num_dict_ibr = {
        'ret': 0,
        'call': 0,
        'jmp': 0,
        'int': 0,
        'syscall': 0
    }

    num_call_preceded = num_system_call = 0
    is_call_preceded = is_system_call = False

    num_g_fun = num_g_nop = num_g_normal = 0
    fun_len_list, nop_len_list, normal_len_list = [], [], []

    # length of current code fragment
    length = 0

    # result container
    details = {}
    # result key
    cur_addr = ''

    def write(line=''):
        output.write('{}\n'.format(line))

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            # print line

            # overview
            if line.startswith('+'):
                write(line)

            # length
            elif line.startswith('>'):
                length = int(line.split()[-1])

            # instruction
            elif line.startswith('|'):
                # print line

                if length == 1:
                    inst = line.split('\t')[1]
                    infos = line.split()
                    cur_addr, br_type = infos[1].split(':')[-1], infos[2]
                    if br_type == 'rep' or br_type == 'retn':
                        br_type = 'ret'

                    num_dict_ibr[br_type] += 1

                    details[cur_addr] = {
                        'br': br_type,
                        'addr': cur_addr,
                        'inst': inst,
                        'types': set(),
                        'clobbers': set(),
                        'fun_maxlen': 0,
                        'nop_maxlen': 0,
                        'call-preceded': False
                    }

                d = details[cur_addr]

                # clobbers
                matched_1 = re.match(pattern1, line)
                matched_2 = re.match(pattern2, line)
                if matched_1:
                    reg = matched_1.group('reg')
                    d['clobbers'].add(reg)
                if matched_2:
                    opcode = matched_2.group('opcode')
                    if opcode == 'enter':
                        d['clobbers'].add('ebp')
                    elif opcode == 'leave':
                        d['clobbers'].add('ebp')
                        d['clobbers'].add('esp')

            # call preceded
            elif line.startswith('*'):
                is_call_preceded = False if line.startswith('* not') else True
                if is_call_preceded:
                    num_call_preceded += 1

            # system call
            elif line.startswith('!'):
                is_system_call = False if line.startswith('! not') else True
                if is_system_call:
                    num_system_call += 1

            # function entry
            elif line.startswith('['):
                write(line)

            # code
            elif not line.startswith('=') and not line.startswith('-'):
                code = binascii.a2b_hex(line)

                cl = classifier.GadgetClassifier(arch=archinfo.ArchX86(
                ), validate_gadgets=False, log_level=logging.DEBUG)
                gadget = cl.is_gadget(code, 0x40000)

                # functional gadget
                if len(gadget) > 0:
                    num_g_fun += 1

                    d['types'] |= set([str(g).split('(')[0] for g in gadget])
                    d['fun_maxlen'] = max(length, d['fun_maxlen'])
                    d['call-preceded'] = is_call_preceded

                # nop gadget
                elif len(d['clobbers']) < NOP_LIMIT:
                    num_g_nop += 1
                    d['nop_maxlen'] = max(length, d['nop_maxlen'])

                # normal code
                else:
                    num_g_normal += 1
                    normal_len_list.append(length)

    write('|-- ret: {}'.format(num_dict_ibr['ret']))
    write('|-- jmp: {}'.format(num_dict_ibr['jmp']))
    write('|-- call: {}'.format(num_dict_ibr['call']))
    write('|-- system call: {}'.format(num_system_call))
    write('|-- call preceded: {}'.format(num_call_preceded))
    write()
    write()
    write()

    for d in details.itervalues():
        fun_len_list.append(d['fun_maxlen'])
        nop_len_list.append(d['nop_maxlen'])

        if d['types']:
            write()
            write('[Gadget]')
            write('0x{:0>8}:               {}'.format(d['addr'], d['inst']))
            write('Types:                    {}'.format(
                ', '.join(list(d['types']))))
            write('Clobbers:                 {}'.format(
                ', '.join(list(d['clobbers']))))
            write('Functional Max length:    {}'.format(d['fun_maxlen']))
            write('Nop Max length:           {}'.format(d['nop_maxlen']))
            write('Call preceded:            {}'.format(d['call-preceded']))

        # mmy
        fragment_type = ''
        if d['fun_maxlen'] > 0:
            fragment_type = 'Functional'
        elif d['nop_maxlen'] > 0:
            fragment_type = 'NOP'
        else:
            fragment_type = 'Normal code'
        pin.write('{}\t{:<12}\t{}\t{}\n'.format(d['addr'].lower(), fragment_type, d['fun_maxlen'], d['nop_maxlen']))

    write()
    write('+ Functional gadgets: {}'.format(num_g_fun))
    write('|-- Fun Max length: {}'.format(max(fun_len_list)))
    write('|-- Fun Min length: {}'.format(min(fun_len_list)))
    write('|-- Fun Avg length: {:.2f}'.format(
        sum(fun_len_list) / len(fun_len_list)))
    write()
    write('+ Nop gadgets(LIMIT={}): {}'.format(NOP_LIMIT, num_g_nop))
    write('|-- Nop Max length: {}'.format(max(nop_len_list)))
    write('|-- Nop Min length: {}'.format(min(nop_len_list)))
    write('|-- Nop Avg length: {:.2f}'.format(
        sum(nop_len_list) / len(nop_len_list)))
    write()
    write('+ Normal code fragments: {}'.format(num_g_normal))
    write('|-- NCF Max length: {}'.format(max(normal_len_list)
                                          if normal_len_list else 0))
    write('|-- NCF Min length: {}'.format(min(normal_len_list)
                                          if normal_len_list else 0))
    write('|-- NCF Avg length: {:.2f}'.format(
        sum(normal_len_list) / len(normal_len_list)
        if normal_len_list else 0))

    output.close()
