from pwn import *

io = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return io.recvuntil(b'> ')

def register_manifest(count, size):
    io.sendline(b'1')
    io.recvuntil(b'How many items? ')
    io.sendline(str(count).encode())
    io.recvuntil(b'Size per item? ')
    io.sendline(str(size).encode())
    res = io.recvuntil(b'> ')
    return res

def view_manifest(idx):
    io.sendline(b'2')
    io.recvuntil(b'ID: ')
    io.sendline(str(idx).encode())
    res = io.recvuntil(b'> ')
    return res

def inspect_manifest(idx, index):
    io.sendline(b'3')
    io.recvuntil(b'ID: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Index: ')
    io.sendline(str(index).encode())
    res = io.recvuntil(b'> ')
    return res

def delete_manifest(idx):
    io.sendline(b'4')
    io.recvuntil(b'ID: ')
    io.sendline(str(idx).encode())
    res = io.recvuntil(b'> ')
    return res

print(recv_menu().decode())
print("Registering manifest...")
print(register_manifest(10, 16).decode())
print("Inspecting manifest at index 0...")
print(inspect_manifest(0, 0).decode())

io.close()
