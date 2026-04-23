from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

recv_menu()
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
# We need to trigger an integer overflow when calculating allocation size
# The code seems to do:
# item_count = r15d
# item_size = r14d
# alloc_size = item_count * item_size (as 32-bit imul, but then casted to 16-bit? Wait, let's look at objdump output)
# mov %r15d, %edi ; imul %r14d, %edi ; test %di, %di ... movzwl %di, %edi ; call malloc
# So allocation size is only the lower 16 bits of item_count * item_size!
# But later it reads `item_count * item_size` bytes (maybe calculated with 64-bit imul?):
# movzwl %r15w, %ebp ; movzwl %r14w, %eax ; imul %rax, %rbp
# So if we make (item_count * item_size) large but the lower 16 bits small, we overflow!
# Let's say item_count * item_size = 0x10008. The lower 16 bits is 8. malloc(8) is called.
# But it reads 0x10008 bytes!
# Wait, item_count is %r15w (16-bit), item_size is %r14w (16-bit).
# Max value is 0xffff * 0xffff = 0xfffe0001.
# Let's choose item_count = 0x100 (256) and item_size = 0x100 (256).
# 256 * 256 = 65536 = 0x10000.
# The lower 16 bits is 0.
# If %di is 0, it does `mov $0x1, %eax; cmove %eax, %edi`. So it allocates 1 byte.
# And it reads 65536 bytes into it!
#
# What's next? `malloc` returns a chunk. We can overwrite the next chunk.
# But what is being read? The cargo data.
# The `Checkpoint` is probably a function pointer or address?
# Let's see the global layout.
# The target is probably `Checkpoint`. Let's check where it is stored in relation to the allocated chunk.
# Wait, is `Checkpoint` in `.bss`?
# In one output, Checkpoint was 0x55de2910e2a0, and Validator was 0x55ddfcb8e36c.
# That's a huge difference. Checkpoint is a heap address!
# Ah, the `Checkpoint` is just the `malloc` returned pointer.
# Wait, no. "Validator" is a code address (0x55ddfcb8e36c). "Checkpoint" is 0x55de2910e2a0.
# Let's verify.
p.close()
