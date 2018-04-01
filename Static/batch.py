import os
import subprocess

idaq = '/Applications/idaq.app/Contents/MacOS/idaq'
elf_dir = 'elf/'
txt_dir = 'fragment/'
script = 'gcollector.py'

elfs = os.listdir(elf_dir)

# collect code fragments
for elf in elfs:
    output = ''.join([txt_dir, elf, '.txt'])
    with open(output, 'w') as f:
        arg_S = ''.join(['-S"../', script, ' ../', output, '"'])
        arg_elf = elf_dir + elf
        cmd = ' '.join([idaq, arg_S, arg_elf])
        print cmd
        subprocess.call(cmd, shell=True)

# validate gadgets
subprocess.call('python gvalidator.py', shell=True)

# analyze gadgets
subprocess.call('python ganalyzer.py', shell=True)
