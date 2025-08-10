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
        self.rte_patterns = [
            'Rte_Call_', 'Rte_Read_', 'Rte_Write_', 'Rte_Send_', 'Rte_Receive_',
            'Rte_IRead_', 'Rte_IWrite_', 'Rte_IrvRead_', 'Rte_IrvWrite_',
            'Rte_Prm_', 'Rte_CData_', 'Rte_Pim_', 'Rte_Enter_', 'Rte_Exit_',
            'Rte_Mode_', 'Rte_Switch_', 'Rte_Trigger_', 'Rte_Feedback_'
        ]
        self.rte_functions = set()
        self.rte_mappings = {}  # Maps RTE calls to actual implementation functions
        
        self._load_file()
        self._parse_elf_header()
        self._parse_section_headers()
        self._parse_symbols()
        self._identify_rte_functions()
        self._analyze_rte_mappings()
        self._analyze_calls()
        self._analyze_rte_calls()
    
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
    
    def _identify_rte_functions(self):
        """Identify RTE functions and related patterns"""
        for func_name in self.functions:
            # Check if function matches RTE patterns
            if any(func_name.startswith(pattern) for pattern in self.rte_patterns):
                self.rte_functions.add(func_name)
        
        # Also check symbols for RTE patterns
        for sym_name in self.symbols:
            if any(sym_name.startswith(pattern) for pattern in self.rte_patterns):
                self.rte_functions.add(sym_name)
    
    def _analyze_rte_mappings(self):
        """Analyze RTE function mappings to actual implementations"""
        # Look for common RTE mapping patterns
        
        # Pattern 1: Direct mapping through naming convention
        # Rte_Call_ComponentName_PortName_OperationName -> ComponentName_OperationName
        for rte_func in self.rte_functions:
            if rte_func.startswith('Rte_Call_'):
                # Extract component and operation name
                parts = rte_func.replace('Rte_Call_', '').split('_')
                if len(parts) >= 3:
                    component = parts[0]
                    operation = parts[-1]  # Last part is usually the operation
                    
                    # Look for potential implementation functions
                    possible_impl = f"{component}_{operation}"
                    if possible_impl in self.functions:
                        self.rte_mappings[rte_func] = possible_impl
                    
                    # Also try without component prefix
                    if operation in self.functions:
                        self.rte_mappings[rte_func] = operation
            
            # Pattern 2: Rte_Read/Write mappings
            elif rte_func.startswith(('Rte_Read_', 'Rte_Write_', 'Rte_IRead_', 'Rte_IWrite_')):
                # These might map to getter/setter functions
                parts = rte_func.split('_')
                if len(parts) >= 3:
                    data_element = parts[-1]
                    
                    # Look for getter/setter patterns
                    for getter_pattern in [f"Get{data_element}", f"get{data_element}", f"{data_element}_Get"]:
                        if getter_pattern in self.functions:
                            self.rte_mappings[rte_func] = getter_pattern
                            break
                    
                    for setter_pattern in [f"Set{data_element}", f"set{data_element}", f"{data_element}_Set"]:
                        if setter_pattern in self.functions:
                            self.rte_mappings[rte_func] = setter_pattern
                            break
        
        # Pattern 3: Look for RTE configuration tables or function pointers
        self._analyze_rte_tables()
    
    def _analyze_rte_tables(self):
        """Analyze RTE configuration tables for function mappings"""
        # Look for common RTE table sections
        rte_sections = ['.rte_config', '.autosar_rte', '.rte_data']
        
        for section in self.section_headers:
            # Check if this might be an RTE configuration section
            section_name = self._get_section_name(section)
            if any(rte_sec in section_name.lower() for rte_sec in rte_sections):
                self._parse_rte_config_section(section)
    
    def _get_section_name(self, section):
        """Get section name from section header"""
        if self.elf_header['e_shstrndx'] >= len(self.section_headers):
            return ""
        
        shstrtab = self.section_headers[self.elf_header['e_shstrndx']]
        shstrtab_data = self.file_data[shstrtab['sh_offset']:shstrtab['sh_offset'] + shstrtab['sh_size']]
        
        return self._get_string(shstrtab_data, section['sh_name'])
    
    def _parse_rte_config_section(self, section):
        """Parse RTE configuration section for function pointers"""
        # This is simplified - real implementation would need to understand
        # the specific RTE configuration format used
        section_data = self.file_data[section['sh_offset']:section['sh_offset'] + section['sh_size']]
        
        # Look for function addresses in the configuration data
        ptr_size = 8 if self.is_64bit else 4
        for i in range(0, len(section_data) - ptr_size, ptr_size):
            if self.is_64bit:
                addr = struct.unpack('<Q', section_data[i:i+8])[0]
            else:
                addr = struct.unpack('<I', section_data[i:i+4])[0]
            
            # Check if this address corresponds to a known function
            target_func = self._find_function_by_address(addr)
            if target_func:
                # This might be an RTE mapping - we'd need more context to determine the source
                pass
    
    def _analyze_rte_calls(self):
        """Analyze RTE function calls and add them to call graph"""
        # Add RTE mappings to call graph
        for rte_func, impl_func in self.rte_mappings.items():
            if rte_func in self.functions and impl_func in self.functions:
                self.call_graph[rte_func].add(impl_func)
                self.reverse_call_graph[impl_func].add(rte_func)
        
        # Look for functions that call RTE functions and connect them to implementations
        for caller, callees in list(self.call_graph.items()):
            for callee in list(callees):
                if callee in self.rte_mappings:
                    impl_func = self.rte_mappings[callee]
                    if impl_func in self.functions:
                        # Add direct connection from caller to implementation
                        self.call_graph[caller].add(impl_func)
                        self.reverse_call_graph[impl_func].add(caller)
    
    def _find_rte_connected_functions(self) -> Set[str]:
        """Find functions that are connected through RTE calls"""
        rte_connected = set()
        
        # Add all RTE functions
        rte_connected.update(self.rte_functions)
        
        # Add all functions that are implementations of RTE calls
        rte_connected.update(self.rte_mappings.values())
        
        # Add functions that call RTE functions
        for caller, callees in self.call_graph.items():
            if any(callee in self.rte_functions for callee in callees):
                rte_connected.add(caller)
        
        # Add functions that are called by RTE functions
        for rte_func in self.rte_functions:
            if rte_func in self.call_graph:
                rte_connected.update(self.call_graph[rte_func])
        
        return rte_connected
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
        """Find dead (unreachable) functions using BFS from entry points, considering RTE connections"""
        if entry_points is None:
            entry_points = ['main', '_start', '__libc_start_main']
        
        # Find actual entry points that exist in our functions
        actual_entry_points = []
        for ep in entry_points:
            if ep in self.functions:
                actual_entry_points.append(ep)
        
        # Add RTE-connected functions as potential entry points
        # In AUTOSAR, RTE functions can be called by the runtime environment
        rte_connected = self._find_rte_connected_functions()
        for func in rte_connected:
            if func in self.functions and func not in actual_entry_points:
                actual_entry_points.append(func)
        
        # Add interrupt handlers and callback functions (common patterns)
        interrupt_patterns = ['ISR_', 'Handler_', '_IRQ', '_Handler', 'Callback_', '_Callback']
        for func in self.functions:
            if any(pattern in func for pattern in interrupt_patterns):
                if func not in actual_entry_points:
                    actual_entry_points.append(func)
        
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
            
            # If this is an RTE function, add its mapped implementation
            if current in self.rte_mappings:
                impl_func = self.rte_mappings[current]
                if impl_func not in visited and impl_func in self.functions:
                    queue.append(impl_func)
        
        # Dead functions are all functions minus reachable ones
        all_functions = set(self.functions.keys())
        dead_functions = all_functions - visited
        
        return dead_functions
    
    def _write_output(self, content: str, output_file):
        """Write content to output file or stdout"""
        if output_file:
            output_file.write(content)
        else:
            print(content, end='')
    
    def print_call_graph(self, output_file=None):
        """Print the call graph"""
        self._write_output("\n=== CALL GRAPH ===\n", output_file)
        for caller, callees in sorted(self.call_graph.items()):
            self._write_output(f"{caller}:\n", output_file)
            for callee in sorted(callees):
                self._write_output(f"  -> {callee}\n", output_file)
        
        self._write_output(f"\nTotal functions with calls: {len(self.call_graph)}\n", output_file)
    
    def print_dead_code_analysis(self, output_file=None):
        """Print dead code analysis results"""
        dead_funcs = self.find_dead_functions()
        rte_connected = self._find_rte_connected_functions()
        
        self._write_output("\n=== DEAD CODE ANALYSIS ===\n", output_file)
        self._write_output(f"Total functions: {len(self.functions)}\n", output_file)
        self._write_output(f"RTE-connected functions: {len(rte_connected)}\n", output_file)
        self._write_output(f"Dead functions: {len(dead_funcs)}\n", output_file)
        
        if dead_funcs:
            self._write_output("\nDead functions:\n", output_file)
            for func in sorted(dead_funcs):
                func_info = self.functions[func]
                # Check if this function has RTE patterns but still marked as dead
                rte_note = ""
                if any(func.startswith(pattern) for pattern in self.rte_patterns):
                    rte_note = " [RTE-related]"
                elif func in rte_connected:
                    rte_note = " [RTE-connected]"
                
                self._write_output(f"  {func} (addr: 0x{func_info['address']:x}, size: {func_info['size']}){rte_note}\n", output_file)
        else:
            self._write_output("No dead functions found!\n", output_file)
        
        # Additional RTE analysis
        self._write_output(f"\n=== RTE ANALYSIS ===\n", output_file)
        self._write_output(f"RTE functions identified: {len(self.rte_functions)}\n", output_file)
        
        if self.rte_functions:
            self._write_output("\nRTE functions:\n", output_file)
            for rte_func in sorted(self.rte_functions):
                if rte_func in self.functions:
                    mapping_info = ""
                    if rte_func in self.rte_mappings:
                        mapping_info = f" -> {self.rte_mappings[rte_func]}"
                    self._write_output(f"  {rte_func}{mapping_info}\n", output_file)
        
        if self.rte_mappings:
            self._write_output(f"\nRTE mappings found: {len(self.rte_mappings)}\n", output_file)
            for rte_func, impl_func in sorted(self.rte_mappings.items()):
                self._write_output(f"  {rte_func} -> {impl_func}\n", output_file)
    
    def print_statistics(self, output_file=None):
        """Print overall statistics"""
        self._write_output("\n=== STATISTICS ===\n", output_file)
        self._write_output(f"File: {self.filename}\n", output_file)
        self._write_output(f"Architecture: {'64-bit' if self.is_64bit else '32-bit'}\n", output_file)
        self._write_output(f"Total symbols: {len(self.symbols)}\n", output_file)
        self._write_output(f"Total functions: {len(self.functions)}\n", output_file)
        self._write_output(f"RTE functions identified: {len(self.rte_functions)}\n", output_file)
        self._write_output(f"RTE mappings found: {len(self.rte_mappings)}\n", output_file)
        self._write_output(f"Functions with outgoing calls: {len(self.call_graph)}\n", output_file)
        self._write_output(f"Functions with incoming calls: {len(self.reverse_call_graph)}\n", output_file)
        
        # Calculate some metrics
        if self.functions:
            max_calls_out = max(len(callees) for callees in self.call_graph.values()) if self.call_graph else 0
            max_calls_in = max(len(callers) for callers in self.reverse_call_graph.values()) if self.reverse_call_graph else 0
            
            self._write_output(f"Max outgoing calls from a function: {max_calls_out}\n", output_file)
            self._write_output(f"Max incoming calls to a function: {max_calls_in}\n", output_file)
        
        # RTE-specific statistics
        rte_connected = self._find_rte_connected_functions()
        self._write_output(f"Functions connected to RTE: {len(rte_connected)}\n", output_file)
    
    def export_call_graph_dot(self, filename: str):
        """Export call graph in DOT format for visualization with Graphviz"""
        with open(filename, 'w') as f:
            f.write("digraph CallGraph {\n")
            f.write("  rankdir=LR;\n")
            f.write("  node [shape=box];\n\n")
            
            # Add all function nodes
            for func in self.functions:
                f.write(f'  "{func}";\n')
            
            f.write("\n")
            
            # Add edges
            for caller, callees in self.call_graph.items():
                for callee in callees:
                    f.write(f'  "{caller}" -> "{callee}";\n')
            
            f.write("}\n")
    
    def export_dead_code_report(self, filename: str):
        """Export detailed dead code report"""
        dead_funcs = self.find_dead_functions()
        rte_connected = self._find_rte_connected_functions()
        
        with open(filename, 'w') as f:
            f.write("DEAD CODE ANALYSIS REPORT (RTE-AWARE)\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"File: {self.filename}\n")
            f.write(f"Analysis Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("SUMMARY:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total functions: {len(self.functions)}\n")
            f.write(f"RTE functions identified: {len(self.rte_functions)}\n")
            f.write(f"RTE-connected functions: {len(rte_connected)}\n")
            f.write(f"Live functions: {len(self.functions) - len(dead_funcs)}\n")
            f.write(f"Dead functions: {len(dead_funcs)}\n")
            if self.functions:
                dead_percentage = (len(dead_funcs) / len(self.functions)) * 100
                f.write(f"Dead code percentage: {dead_percentage:.2f}%\n")
            
            f.write("\nRTE MAPPINGS:\n")
            f.write("-" * 20 + "\n")
            if self.rte_mappings:
                for rte_func, impl_func in sorted(self.rte_mappings.items()):
                    f.write(f"{rte_func} -> {impl_func}\n")
            else:
                f.write("No RTE mappings detected.\n")
            
            f.write("\nDEAD FUNCTIONS:\n")
            f.write("-" * 20 + "\n")
            
            if dead_funcs:
                total_dead_size = 0
                rte_related_dead = 0
                
                for func in sorted(dead_funcs):
                    func_info = self.functions[func]
                    is_rte_related = any(func.startswith(pattern) for pattern in self.rte_patterns)
                    
                    f.write(f"Function: {func}\n")
                    f.write(f"  Address: 0x{func_info['address']:x}\n")
                    f.write(f"  Size: {func_info['size']} bytes\n")
                    f.write(f"  Section: {func_info['section']}\n")
                    
                    if is_rte_related:
                        f.write(f"  Note: RTE-related function\n")
                        rte_related_dead += 1
                    
                    f.write("\n")
                    total_dead_size += func_info['size']
                
                f.write(f"Total dead code size: {total_dead_size} bytes\n")
                f.write(f"RTE-related dead functions: {rte_related_dead}\n")
            else:
                f.write("No dead functions found.\n")
            
            f.write("\nPOTENTIAL FALSE POSITIVES:\n")
            f.write("-" * 30 + "\n")
            f.write("Functions that might be incorrectly marked as dead:\n")
            f.write("- Interrupt handlers not following naming conventions\n")
            f.write("- Functions called through RTE patterns not detected\n")
            f.write("- Callback functions registered at runtime\n")
            f.write("- Functions called through function pointers\n")
            f.write("- AUTOSAR runnable entities called by RTE scheduler\n")
    
    def export_full_report(self, filename: str):
        """Export comprehensive analysis report"""
        with open(filename, 'w') as f:
            self.print_statistics(f)
            self.print_call_graph(f)
            self.print_dead_code_analysis(f)
            
            # Additional detailed information
            f.write("\n=== FUNCTION DETAILS ===\n")
            for func_name in sorted(self.functions.keys()):
                func_info = self.functions[func_name]
                f.write(f"\n{func_name}:\n")
                f.write(f"  Address: 0x{func_info['address']:x}\n")
                f.write(f"  Size: {func_info['size']} bytes\n")
                f.write(f"  Section: {func_info['section']}\n")
                
                # Outgoing calls
                if func_name in self.call_graph:
                    f.write(f"  Calls: {', '.join(sorted(self.call_graph[func_name]))}\n")
                else:
                    f.write("  Calls: none\n")
                
                # Incoming calls
                if func_name in self.reverse_call_graph:
                    f.write(f"  Called by: {', '.join(sorted(self.reverse_call_graph[func_name]))}\n")
                else:
                    f.write("  Called by: none\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='ELF Call Graph and Dead Code Analyzer')
    parser.add_argument('elf_file', help='Path to ELF file to analyze')
    parser.add_argument('-o', '--output', help='Output file for full report')
    parser.add_argument('--call-graph-dot', help='Export call graph in DOT format')
    parser.add_argument('--dead-code-report', help='Export detailed dead code report')
    parser.add_argument('--console', action='store_true', help='Also print to console (default if no output specified)')
    
    args = parser.parse_args()
    
    try:
        analyzer = ELFAnalyzer(args.elf_file)
        
        # If no output files specified, print to console
        if not any([args.output, args.call_graph_dot, args.dead_code_report]):
            args.console = True
        
        # Console output
        if args.console:
            analyzer.print_statistics()
            analyzer.print_call_graph()
            analyzer.print_dead_code_analysis()
        
        # Full report output
        if args.output:
            analyzer.export_full_report(args.output)
            print(f"Full report exported to: {args.output}")
        
        # Call graph DOT export
        if args.call_graph_dot:
            analyzer.export_call_graph_dot(args.call_graph_dot)
            print(f"Call graph (DOT format) exported to: {args.call_graph_dot}")
            print("Visualize with: dot -Tpng -o callgraph.png " + args.call_graph_dot)
        
        # Dead code report
        if args.dead_code_report:
            analyzer.export_dead_code_report(args.dead_code_report)
            print(f"Dead code report exported to: {args.dead_code_report}")
            
    except Exception as e:
        print(f"Error analyzing {args.elf_file}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()