from idautils import *
from idc import *
from datetime import datetime

idc.Wait()

total_insts = 0
br_insts = 0
ibr_insts = 0
funcs = 0
insts_container = []

BR = '(\.\S+)\s(call|ret|rep ret|int|iret|j)'
IBR = '(\.\S+)\s(call|ret|rep ret|int\s80h|iret)'
call_preceded = False

filePath = ARGV[1]
f = open(filePath, 'w')


def dec2hex(num):
    hex_num = hex(num).replace('0x', '')
    hex_num = '0' + hex_num if len(hex_num) < 2 else hex_num
    return hex_num


def disasm(head):
    inst_line = atoa(head) + '\t' + GetDisasm(head)

    # returns length of the instruction in bytes
    inst_bytes_num = MakeCode(head)
    inst_list = [dec2hex(Byte(head + i)) for i in range(inst_bytes_num)]
    inst_code = ''.join(inst_list)

    return inst_code, inst_line


print 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
time_start = datetime.now()

for seg_head in Segments():
    seg_name, start, end = SegName(seg_head), seg_head, SegEnd(seg_head)

    # print '============================'
    # print seg_head, seg_name
    if seg_name == 'extern':
        continue

    if not isCode(GetFlags(seg_head)):
        continue

    # instruction
    for head in Heads(start, end):
        total_insts += 1

        inst_code, inst_line = disasm(head)
        insts_container.append((inst_code, inst_line))

        # pretty_inst_str = ' ' * 4 + inst_code + ' ' * (32 - len(inst_code))
        # print atoa(head), pretty_inst_str, inst_line

        if re.match(BR, inst_line):
            br_insts += 1

            direct_call = inst_code.startswith('e8')
            indirect_jmp = inst_code.startswith(
                'ff') or inst_code.startswith('ea')
            syscall = inst_code.startswith(
                '65ff') or inst_code.startswith(
                'cd80') or inst_code.startswith('0f05')

            # indirect branch
            if re.match(IBR, inst_line) \
                    and 'push' not in inst_line \
                    and not direct_call \
                    or indirect_jmp \
                    or syscall:
                ibr_insts += 1

                # syscall
                if syscall:
                    f.write('! syscall\n')
                else:
                    f.write('! not syscall\n')

                # call-preceded
                if call_preceded:
                    f.write('* call-preceded\n')
                else:
                    f.write('* not call-preceded\n')
                call_preceded = True if re.match(
                    '.*\s(call)', inst_line) else False

                # fragments
                length = len(insts_container)
                for i in xrange(1, length + 1):
                    # codes_list, insts_list = zip(*insts_container[-i:])
                    codes_list, insts_list = [], []
                    for code, inst in insts_container[-i:]:
                        codes_list.append(code)
                        insts_list.append(inst)

                    codes = ''.join(codes_list)

                    f.write('> length: ' + str(i) + '\n')
                    for inst in insts_list:
                        f.write('|-- ' + inst + '\n')
                    f.write(codes + '\n')
                    f.write('-' * 40 + '\n')

                f.write('=' * 60 + '\n')

            insts_container = []


for seg_head in Segments():
    seg_name, start, end = SegName(seg_head), seg_head, SegEnd(seg_head)
    # func entry
    for entry in Functions(start, end):
        funcs += 1
        func_name = GetFunctionName(entry)
        f.write('[Func]\t0x{:x}\t{}\n'.format(entry, func_name))


print 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
time_end = datetime.now()
print str(time_end)
print str(time_end - time_start)

f.write('+ Functions: {}\n'.format(funcs))
f.write('+ Instructions: {}\n'.format(total_insts))
f.write('+ Branch instructions: {}\n'.format(br_insts))
f.write('+ Indirect branch instructions: {}\n'.format(ibr_insts))

f.close()

idc.Exit(0)
