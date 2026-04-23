from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

print(recv_menu().decode())
p.sendline(b'1')
print(p.recvuntil(b'Manifest ID (0-15): ').decode())
p.sendline(b'0')
print(p.recv(1024, timeout=2).decode())

p.close()
