savedcmd_sysentinel_metrics.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o sysentinel_metrics.o @sysentinel_metrics.mod  ; /usr/src/kernels/7.1.8-200.fc44.x86_64/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module sysentinel_metrics.o

sysentinel_metrics.o: $(wildcard /usr/src/kernels/7.1.8-200.fc44.x86_64/tools/objtool/objtool)
