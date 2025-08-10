#!/usr/bin/env python3
"""
ELF Call Graph and Dead Code Analyzer
Analyzes ELF files to build call graphs and identify dead code
"""

import struct
import sys
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque
import re

class ELFAnalyzer:
    def __init__(self, filename: str):
        self.filename = filename
        self.file_data = None
        self.elf_header = {}
        self.section_headers = []
        self.symbols = {}
        self.functions = {}
        self.call_graph = defaultdict(set)
        self.reverse_call_graph = defaultdict(set)
        
        self._load_file()
        self._parse_elf_header()
        self._parse_section_headers()
        self._parse_symbols()
        self._analyze_calls()
    
    def _load_file(self):
        """Load ELF file into memory"""
        try:
            with open(self.filename, 'rb') as f:
                self.file_data = f.read()
        except IOError as e:
            raise Exception(f"Cannot read file {self.filename}: {e}")
    
    def _parse_elf_header(self):
        """Parse ELF header to get basic file information"""
        if len(self.file_data) < 64:
            raise Exception("File too small to be ELF")
        
        # Check ELF magic
        if self.file_data[:4] != b'\x7fELF':
            raise Exception("Not an ELF file")
        
        # Parse based on 32/64 bit
        ei_class = self.file_data[4]
        if ei_class == 1:  # 32-bit
            self.is_64bit = False
            fmt = '<HHIIIIIHHHHHH'  # Little endian 32-bit
            header_size = 52
        elif ei_class == 2:  # 64-bit
            self.is_64bit = True
            fmt = '<HHIQQQIHHHHHH'  # Little endian 64-bit
            header_size = 64
        else:
            raise Exception("Invalid ELF class")
        
        header_data = struct.unpack(fmt, self.file_data[16:header_size])
        
        self.elf_header = {
            'e_type': header_data[0],
            'e_machine': header_data[1],
            'e_version': header_data[2],
            'e_entry': header_data[3],
            'e_phoff': header_data[4],
            'e_shoff': header_data[5],
            'e_flags': header_data[6],
            'e_ehsize': header_data[7],
            'e_phentsize': header_data[8],
            'e_phnum': header_data[9],
            'e_shentsize': header_data[10],
            'e_shnum': header_data[11],
            'e_shstrndx': header_data[12]
        }
    
    def _parse_section_headers(self):
        """Parse section headers"""
        shoff = self.elf_header['e_shoff']
        shentsize = self.elf_header['e_shentsize']
        shnum = self.elf_header['e_shnum']
        
        if self.is_64bit:
            fmt = '<IIQQQQIIQQ'
        else:
            fmt = '<IIIIIIIIII'
        
        for i in range(shnum):
            offset = shoff + i * shentsize
            if offset + shentsize > len(self.file_data):
                break
                
            section_data = struct.unpack(fmt, self.file_data[offset:offset + shentsize])
            
            section = {
                'sh_name': section_data[0],
                'sh_type': section_data[1],
                'sh_flags': section_data[2],
                'sh_addr': section_data[3],
                'sh_offset': section_data[4],
                'sh_size': section_data[5],
                'sh_link': section_data[6],
                'sh_info': section_data[7],
                'sh_addralign': section_data[8],
                'sh_entsize': section_data[9]
            }
            
            self.section_headers.append(section)
    
    def _get_section_by_type(self, sh_type: int):
        """Get section by type"""
        for section in self.section_headers:
            if section['sh_type'] == sh_type:
                return section
        return None
    
    def _get_string(self, strtab_data: bytes, offset: int) -> str:
        """Extract null-terminated string from string table"""
        end = strtab_data.find(b'\x00', offset)
        if end == -1:
            end = len(strtab_data)
        return strtab_data[offset:end].decode('utf-8', errors='ignore')
    
    def _parse_symbols(self):
        """Parse symbol table to extract function symbols"""
        # Look for symbol table (.symtab) and dynamic symbol table (.dynsym)
        symtab = self._get_section_by_type(2)  # SHT_SYMTAB
        dynsym = self._get_section_by_type(11)  # SHT_DYNSYM
        
        for sym_section in [symtab, dynsym]:
            if not sym_section:
                continue
                
            # Get corresponding string table
            if sym_section['sh_link'] >= len(self.section_headers):
                continue
            strtab_section = self.section_headers[sym_section['sh_link']]
            
            # Read string table
            strtab_data = self.file_data[strtab_section['sh_offset']:
                                      strtab_section['sh_offset'] + strtab_section['sh_size']]
            
            # Parse symbols
            sym_size = 24 if self.is_64bit else 16
            sym_count = sym_section['sh_size'] // sym_size
            
            for i in range(sym_count):
                sym_offset = sym_section['sh_offset'] + i * sym_size
                
                if self.is_64bit:
                    fmt = '<IBBHQQ'
                else:
                    fmt = '<IIIBBH'
                
                sym_data = struct.unpack(fmt, self.file_data[sym_offset:sym_offset + sym_size])
                
                name_offset = sym_data[0]
                if name_offset == 0:
                    continue
                    
                name = self._get_string(strtab_data, name_offset)
                if not name:
                    continue
                
                if self.is_64bit:
                    info, other, shndx, value, size = sym_data[1:6]
                else:
                    value, size, info, other, shndx = sym_data[1:6]
                
                # Check if it's a function (STT_FUNC = 2)
                sym_type = info & 0xf
                if sym_type == 2:  # STT_FUNC
                    self.functions[name] = {
                        'address': value,
                        'size': size,
                        'section': shndx
                    }
                
                self.symbols[name] = {
                    'address': value,
                    'size': size,
                    'type': sym_type,
                    'section': shndx
                }
    
    def _analyze_calls(self):
        """Analyze call instructions to build call graph"""
        text_section = None
        for section in self.section_headers:
            if section['sh_type'] == 1 and section['sh_flags'] & 0x4:  # SHT_PROGBITS with EXEC flag
                text_section = section
                break
        
        if not text_section:
            return
        
        # Get .text section data
        text_data = self.file_data[text_section['sh_offset']:
                                 text_section['sh_offset'] + text_section['sh_size']]
        text_addr = text_section['sh_addr']
        
        # Simple x86/x86_64 call instruction detection
        # This is a simplified approach - a full implementation would need a proper disassembler
        self._find_calls_x86(text_data, text_addr)
    
    def _find_calls_x86(self, code: bytes, base_addr: int):
        """Find call instructions in x86/x86_64 code"""
        i = 0
        while i < len(code) - 5:
            # Look for call instruction (0xE8 for relative call)
            if code[i] == 0xE8:
                # Extract 32-bit relative offset
                offset = struct.unpack('<i', code[i+1:i+5])[0]
                call_addr = base_addr + i
                target_addr = call_addr + 5 + offset  # +5 for instruction length
                
                # Find caller function
                caller = self._find_function_by_address(call_addr)
                # Find target function
                target = self._find_function_by_address(target_addr)
                
                if caller and target:
                    self.call_graph[caller].add(target)
                    self.reverse_call_graph[target].add(caller)
                
                i += 5
            else:
                i += 1
    
    def _find_function_by_address(self, addr: int) -> Optional[str]:
        """Find function name by address"""
        for name, func_info in self.functions.items():
            func_addr = func_info['address']
            func_size = func_info['size']
            if func_addr <= addr < func_addr + func_size:
                return name
        return None
    
    def get_call_graph(self) -> Dict[str, Set[str]]:
        """Get the call graph"""
        return dict(self.call_graph)
    
    def find_dead_functions(self, entry_points: List[str] = None) -> Set[str]:
        """Find dead (unreachable) functions using BFS from entry points"""
        if entry_points is None:
            entry_points = ['main', '_start', '__libc_start_main']
        
        # Find actual entry points that exist in our functions
        actual_entry_points = []
        for ep in entry_points:
            if ep in self.functions:
                actual_entry_points.append(ep)
        
        # If no standard entry points found, use all externally visible functions
        if not actual_entry_points:
            # Functions that are called but not defined (external calls)
            external_calls = set()
            for callees in self.call_graph.values():
                external_calls.update(callees)
            
            # Add functions that might be entry points (not called by others)
            for func in self.functions:
                if func not in self.reverse_call_graph:
                    actual_entry_points.append(func)
        
        if not actual_entry_points:
            # Fallback: consider all functions as potentially reachable
            return set()
        
        # BFS to find all reachable functions
        visited = set()
        queue = deque(actual_entry_points)
        
        while queue:
            current = queue.popleft()
            if current in visited or current not in self.functions:
                continue
            
            visited.add(current)
            
            # Add all functions called by current function
            for callee in self.call_graph.get(current, []):
                if callee not in visited:
                    queue.append(callee)
        
        # Dead functions are all functions minus reachable ones
        all_functions = set(self.functions.keys())
        dead_functions = all_functions - visited
        
        return dead_functions
    
    def print_call_graph(self):
        """Print the call graph"""
        print("\n=== CALL GRAPH ===")
        for caller, callees in sorted(self.call_graph.items()):
            print(f"{caller}:")
            for callee in sorted(callees):
                print(f"  -> {callee}")
        
        print(f"\nTotal functions with calls: {len(self.call_graph)}")
    
    def print_dead_code_analysis(self):
        """Print dead code analysis results"""
        dead_funcs = self.find_dead_functions()
        
        print("\n=== DEAD CODE ANALYSIS ===")
        print(f"Total functions: {len(self.functions)}")
        print(f"Dead functions: {len(dead_funcs)}")
        
        if dead_funcs:
            print("\nDead functions:")
            for func in sorted(dead_funcs):
                func_info = self.functions[func]
                print(f"  {func} (addr: 0x{func_info['address']:x}, size: {func_info['size']})")
        else:
            print("No dead functions found!")
    
    def print_statistics(self):
        """Print overall statistics"""
        print(f"\n=== STATISTICS ===")
        print(f"File: {self.filename}")
        print(f"Architecture: {'64-bit' if self.is_64bit else '32-bit'}")
        print(f"Total symbols: {len(self.symbols)}")
        print(f"Total functions: {len(self.functions)}")
        print(f"Functions with outgoing calls: {len(self.call_graph)}")
        print(f"Functions with incoming calls: {len(self.reverse_call_graph)}")
        
        # Calculate some metrics
        if self.functions:
            max_calls_out = max(len(callees) for callees in self.call_graph.values()) if self.call_graph else 0
            max_calls_in = max(len(callers) for callers in self.reverse_call_graph.values()) if self.reverse_call_graph else 0
            
            print(f"Max outgoing calls from a function: {max_calls_out}")
            print(f"Max incoming calls to a function: {max_calls_in}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python elf_analyzer.py <elf_file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    try:
        analyzer = ELFAnalyzer(filename)
        
        analyzer.print_statistics()
        analyzer.print_call_graph()
        analyzer.print_dead_code_analysis()
        
    except Exception as e:
        print(f"Error analyzing {filename}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
