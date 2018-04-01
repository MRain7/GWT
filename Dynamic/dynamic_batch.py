import os
import subprocess

elf_dir = "elf/"
static_dir = "static_results/"
dynamic_dir = "dynamic_results/"

elfs = os.listdir(elf_dir)
static_results = os.listdir(static_dir)

cp = "cp static_results/"
pin = "../../../pin -t obj-ia32/DynamicAnalysis.so -- "
pwd = os.path.abspath(".")

for elf in elfs:
    for static_result in static_results:
        file_name = "".join([elf, ".txt"])
        if file_name == static_result:
            cmd1 = "".join([cp, static_result, " static_results.txt"])
            subprocess.call(cmd1, shell = True)
            break
        else:
            continue
    cmd2 = "".join([pin, "elf/", elf, " > dynamic_results/", elf, ".txt"])
    subprocess.call(cmd2, shell = True)




