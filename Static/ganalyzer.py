import os
from pprint import pprint

input_dir = 'detail/'
output_dir = 'result.txt'

files = []
func = []
inst = []
br = []
ibr = []
ret = []
jmp = []
call = []
sys = []
call_preceded = []
fun_g = []
fun_max = []
fun_min = []
fun_avg = []
nop_g = []
nop_max = []
nop_min = []
nop_avg = []
ncf_g = []
ncf_max = []
ncf_min = []
ncf_avg = []

output = open(output_dir, 'w')


def write(line=''):
    output.write('{}\n'.format(line))


def avg(l):
    return 1.0 * sum(l) / length


for input_txt in os.listdir(input_dir):
    filename = input_txt.split('.')[0]
    files.append(filename)

    with open(input_dir + input_txt, 'r') as f:
        for line in f:
            if line.startswith('+ Functions:'):
                func.append(int(line.split()[-1]))
            elif line.startswith('+ Ins'):
                inst.append(int(line.split()[-1]))
            elif line.startswith('+ Bra'):
                br.append(int(line.split()[-1]))
            elif line.startswith('+ Ind'):
                ibr.append(int(line.split()[-1]))
            elif line.startswith('|-- ret'):
                ret.append(int(line.split()[-1]))
            elif line.startswith('|-- jmp'):
                jmp.append(int(line.split()[-1]))
            elif line.startswith('|-- call:'):
                call.append(int(line.split()[-1]))
            elif line.startswith('|-- sys'):
                sys.append(int(line.split()[-1]))
            elif line.startswith('|-- call p'):
                call_preceded.append(int(line.split()[-1]))
            elif line.startswith('+ Functional'):
                fun_g.append(int(line.split()[-1]))
            elif line.startswith('|-- Fun Max'):
                fun_max.append(int(line.split()[-1]))
            elif line.startswith('|-- Fun Min'):
                fun_min.append(int(line.split()[-1]))
            elif line.startswith('|-- Fun Avg'):
                fun_avg.append(float(line.split()[-1]))
            elif line.startswith('+ Nop'):
                nop_g.append(int(line.split()[-1]))
            elif line.startswith('|-- Nop Max'):
                nop_max.append(int(line.split()[-1]))
            elif line.startswith('|-- Nop Min'):
                nop_min.append(int(line.split()[-1]))
            elif line.startswith('|-- Nop Avg'):
                nop_avg.append(float(line.split()[-1]))
            elif line.startswith('+ Normal'):
                ncf_g.append(int(line.split()[-1]))
            elif line.startswith('|-- NCF Max'):
                ncf_max.append(int(line.split()[-1]))
            elif line.startswith('|-- NCF Min'):
                ncf_min.append(int(line.split()[-1]))
            elif line.startswith('|-- NCF Avg'):
                ncf_avg.append(float(line.split()[-1]))

pprint(files)

length = len(files)

write(', '.join(files))
write('+ Files: {}'.format(length))
write()

write('+ [AVG]')
write('|-- Functions: {:.2f}'.format(avg(func)))
write('|-- Instructions: {:.2f}'.format(avg(inst)))
write('|-- Branch instructions: {:.2f}'.format(avg(br)))
write('|-- Indirect branch instructions: {:.2f}'.format(avg(ibr)))
write('    |-- ret: {:.2f} ({} ~ {})'.format(avg(ret), min(ret), max(ret)))
write('    |-- jmp: {:.2f} ({} ~ {})'.format(avg(jmp), min(jmp), max(jmp)))
write('    |-- call: {:.2f} ({} ~ {})'.format(avg(call), min(call), max(call)))
write('    |-- system call: {:.2f} ({} ~ {})'.format(
    avg(sys), min(sys), max(sys)))
write('    |-- call preceded: {:.2f} ({} ~ {})'.format(
    avg(call_preceded), min(call_preceded), max(call_preceded)))
write('|-- Functional gadgets: {:.2f}'.format(avg(fun_g)))
write('    |-- length: {:.2f} ({} ~ {})'.format(
    avg(fun_avg), min(fun_min), max(fun_max)))
write('|-- Nop gadgets: {:.2f}'.format(avg(nop_g)))
write('    |-- length: {:.2f} ({} ~ {})'.format(
    avg(nop_avg), min(nop_min), max(nop_max)))
write('|-- Normal code fragments: {:.2f}'.format(avg(ncf_g)))
write('    |-- length: {:.2f} ({} ~ {})'.format(
    avg(ncf_avg), min(ncf_min), max(ncf_max)))

output.close()
