from pwn import *

p = remote("kubenode.mctf.io", 31098)

print(p.recvuntil(b'> ').decode())
p.sendline(b'1')
print(p.recv(1024, timeout=2).decode())

p.close()
