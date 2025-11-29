#!/usr/bin/env python3
"""
BCC to libbpf syntax converter for iptables datapaths

This script converts BPF programs from BCC syntax to libbpf syntax.
It processes all .c files in the datapaths directory and outputs
converted files to the output directory.

Author: Generated for BCC to libbpf migration
"""

import os
import re
import sys
from pathlib import Path

class BCCToLibbpfConverter:
    def __init__(self, input_file=None, output_file=None):
        self.input_file = Path(input_file) if input_file else None
        self.output_file = Path(output_file) if output_file else None
        self.map_definitions = []
        self.global_includes = []
        self.function_definitions = []

    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        if self.output_file:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)

    def extract_map_info(self, bcc_table_line):
        """Extract map information from BCC table definition"""
        # Match patterns like: BPF_TABLE("hash", ct_k, ct_v, ct_table, 65535);
        # and BPF_TABLE_SHARED("percpu_array", int, uint64_t, counters, 10);
        pattern1 = r'BPF_TABLE(?:_SHARED)?\(?["\']([^"\']+)["\'],\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)?'
        match = re.search(pattern1, bcc_table_line)

        if match:
            map_type, key_type, value_type, map_name, max_entries = match.groups()
            # Mark if it's a shared table
            is_shared = 'BPF_TABLE_SHARED' in bcc_table_line
            return {
                'type': map_type.strip(),
                'key_type': key_type.strip(),
                'value_type': value_type.strip(),
                'name': map_name.strip(),
                'max_entries': max_entries.strip(),
                'shared': is_shared
            }

        # Match BPF_HASH(name, key_type, value_type)
        pattern2 = r'BPF_HASH\(\s*([^,]+),\s*([^,]+),\s*([^,]+)\s*\)'
        match = re.search(pattern2, bcc_table_line)
        if match:
            map_name, key_type, value_type = match.groups()
            return {
                'type': 'hash',
                'key_type': key_type.strip(),
                'value_type': value_type.strip(),
                'name': map_name.strip(),
                'max_entries': '10240',  # Default size for BPF_HASH
                'shared': False,
                'original_macro': 'BPF_HASH'
            }

        # Match BPF_ARRAY(name, value_type, size)
        pattern3 = r'BPF_ARRAY\(\s*([^,]+),\s*([^,]+),\s*([^,]+)\s*\)'
        match = re.search(pattern3, bcc_table_line)
        if match:
            map_name, value_type, max_entries = match.groups()
            return {
                'type': 'array',
                'key_type': 'int',  # Default key type for arrays
                'value_type': value_type.strip(),
                'name': map_name.strip(),
                'max_entries': max_entries.strip(),
                'shared': False,
                'original_macro': 'BPF_ARRAY'
            }

        # Match BPF_PERCPU_HASH(name, key_type, value_type)
        pattern4 = r'BPF_PERCPU_HASH\(\s*([^,]+),\s*([^,]+),\s*([^,]+)\s*\)'
        match = re.search(pattern4, bcc_table_line)
        if match:
            map_name, key_type, value_type = match.groups()
            return {
                'type': 'hash',
                'key_type': key_type.strip(),
                'value_type': value_type.strip(),
                'name': map_name.strip(),
                'max_entries': '10240',  # Default size for BPF_PERCPU_HASH
                'shared': True,  # Mark as percpu
                'original_macro': 'BPF_PERCPU_HASH'
            }

        # Match BPF_PERCPU_ARRAY(name, value_type, size)
        pattern5 = r'BPF_PERCPU_ARRAY\(\s*([^,]+),\s*([^,]+),\s*([^,]+)\s*\)'
        match = re.search(pattern5, bcc_table_line)
        if match:
            map_name, value_type, max_entries = match.groups()
            return {
                'type': 'array',
                'key_type': 'int',  # Default key type for arrays
                'value_type': value_type.strip(),
                'name': map_name.strip(),
                'max_entries': max_entries.strip(),
                'shared': True,  # Mark as percpu
                'original_macro': 'BPF_PERCPU_ARRAY'
            }

        # Match BPF_F_TABLE("map_type", key_type, value_type, map_name, size, flags)
        pattern6 = r'BPF_F_TABLE\(\s*["\']([^"\']+)["\'],\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\s*\)'
        match = re.search(pattern6, bcc_table_line)
        if match:
            map_type, key_type, value_type, map_name, max_entries, flags = match.groups()
            return {
                'type': map_type.strip(),
                'key_type': key_type.strip(),
                'value_type': value_type.strip(),
                'name': map_name.strip(),
                'max_entries': max_entries.strip(),
                'flags': flags.strip(),
                'shared': False,
                'original_macro': 'BPF_F_TABLE'
            }

        return None

    def convert_bcc_table_to_libbpf(self, map_info):
        """Convert BCC table definition to libbpf map definition"""
        # Convert BCC table types to libbpf map types
        type_mapping = {
            'hash': 'BPF_MAP_TYPE_HASH',
            'array': 'BPF_MAP_TYPE_ARRAY',
            'percpu_hash': 'BPF_MAP_TYPE_PERCPU_HASH',
            'percpu_array': 'BPF_MAP_TYPE_PERCPU_ARRAY',
            'extern': 'BPF_MAP_TYPE_ARRAY',  # extern maps are typically arrays
            'lpm_trie': 'BPF_MAP_TYPE_LPM_TRIE',
            'queue': 'BPF_MAP_TYPE_QUEUE',
            'stack': 'BPF_MAP_TYPE_STACK'
        }

        bcc_type = map_info['type'].lower()
        libbpf_type = type_mapping.get(bcc_type, 'BPF_MAP_TYPE_HASH')

        # Determine if this is a shared/pinned map
        is_shared_map = False
        is_percpu_map = False

        # Check if it's BPF_TABLE_SHARED or "extern" type
        if map_info.get('shared') or bcc_type == 'extern':
            is_shared_map = True

        # Check if it's a percpu type (either from type name or original macro)
        if 'percpu' in bcc_type.lower() or (map_info.get('original_macro') and 'PERCPU' in map_info['original_macro']):
            is_percpu_map = True
            if libbpf_type == 'BPF_MAP_TYPE_HASH':
                libbpf_type = 'BPF_MAP_TYPE_PERCPU_HASH'
            elif libbpf_type == 'BPF_MAP_TYPE_ARRAY':
                libbpf_type = 'BPF_MAP_TYPE_PERCPU_ARRAY'

        # Generate libbpf map definition with conversion comment
        if map_info.get('original_macro') == 'BPF_F_TABLE':
            # For BPF_F_TABLE with flags
            map_comment = f"// Converted from BPF_F_TABLE('{map_info['type']}', {map_info['key_type']}, {map_info['value_type']}, {map_info['name']}, {map_info['max_entries']}, {map_info['flags']})"

            pinning_line = ""
            if is_shared_map:
                pinning_line = "    __uint(pinning, LIBBPF_PIN_BY_NAME);\n"

            map_def = f"""{map_comment}
struct {{
    __uint(type, {libbpf_type});
    __uint(max_entries, {map_info['max_entries']});
{pinning_line}    __uint(map_flags, {map_info['flags']});
    __type(key, {map_info['key_type']});
    __type(value, {map_info['value_type']});
}} {map_info['name']} SEC(\".maps\");"""
        elif 'original_macro' in map_info:
            # For BPF_HASH, BPF_ARRAY, etc. macros
            map_comment = f"// Converted from {map_info['original_macro']}({map_info['name']}, {map_info['key_type'] if map_info['key_type'] != 'int' else map_info['value_type']}, {map_info['max_entries'] if map_info['key_type'] == 'int' else map_info['value_type']})"

            map_def = f"""{map_comment}
struct {{
    __uint(type, {libbpf_type});
    __uint(max_entries, {map_info['max_entries']});
    __type(key, {map_info['key_type']});
    __type(value, {map_info['value_type']});
}} {map_info['name']} SEC(\".maps\");"""
        else:
            # For BPF_TABLE macros
            map_comment = f"// Converted from BPF_TABLE{('_SHARED' if map_info.get('shared') else '')}('{map_info['type']}', {map_info['key_type']}, {map_info['value_type']}, {map_info['name']}, {map_info['max_entries']})"

            pinning_line = ""
            if is_shared_map:
                pinning_line = "    __uint(pinning, LIBBPF_PIN_BY_NAME);\n"

            map_def = f"""{map_comment}
struct {{
    __uint(type, {libbpf_type});
    __uint(max_entries, {map_info['max_entries']});
{pinning_line}    __type(key, {map_info['key_type']});
    __type(value, {map_info['value_type']});
}} {map_info['name']} SEC(\".maps\");"""

        return map_def

    def convert_headers(self, content):
        """Convert BCC headers to libbpf headers"""
        # Replace BCC specific headers with libbpf headers
        header_replacements = {
            r'#include\s*<bcc/helpers\.h>': '// Converted: #include <bcc/helpers.h> -> #include <bpf/bpf_helpers.h>\n#include <bpf/bpf_helpers.h>',
            r'#include\s*<bcc/proto\.h>': '// Converted: #include <bcc/proto.h> -> #include <linux/bpf.h>\n#include <linux/bpf.h>',
            r'#include\s*<uapi/': '// Converted: #include <uapi/ -> #include <\n#include <'
        }

        for pattern, replacement in header_replacements.items():
            content = re.sub(pattern, replacement, content)

        # Add libbpf headers if not present
        if '<bpf/bpf_helpers.h>' not in content:
            content = '// Added: libbpf helper header\n#include <bpf/bpf_helpers.h>\n' + content

        return content

    def convert_bcc_functions(self, content):
        """Convert BCC specific functions to libbpf functions"""
        # Convert BPF_TABLE_* macros to map access
        function_replacements = {
            r'pcn_log\(\s*ctx,\s*([^,]+),\s*([^)]+)\)': '// Converted: pcn_log -> bpf_printk\nbpf_printk(\2)',
            r'lock_xadd\(\s*&([^,]+),\s*([^)]+)\)': r'// Converted: lock_xadd -> __sync_fetch_and_add\n__sync_fetch_and_add(&\1, \2)',
            r'bpf_skb_pull_data\(\s*([^,]+),\s*([^)]+)\)': '// Converted: bpf_skb_pull_data (same function)\nbpf_skb_pull_data(\1, \2)',
        }

        for pattern, replacement in function_replacements.items():
            content = re.sub(pattern, replacement, content)

        return content

    def convert_bcc_table_usage(self, content):
        """Convert BCC table usage to libbpf map usage"""
        # Convert map access patterns
        # Example: map.lookup(&key) -> bpf_map_lookup_elem(&map, &key)
        content = re.sub(
            r'(\w+)\.lookup\(&?(\w+)\)',
            r'// Converted: \1.lookup() -> bpf_map_lookup_elem()\nbpf_map_lookup_elem(&\1, &\2)',
            content
        )

        # Convert map update patterns
        # Example: map.update(&key, &value) -> bpf_map_update_elem(&map, &key, &value, BPF_ANY)
        content = re.sub(
            r'(\w+)\.update\(&?(\w+),\s*&?(\w+)\)',
            r'// Converted: \1.update() -> bpf_map_update_elem()\nbpf_map_update_elem(&\1, &\2, &\3, BPF_ANY)',
            content
        )

        # Convert map delete patterns
        # Example: map.delete(&key) -> bpf_map_delete_elem(&map, &key)
        content = re.sub(
            r'(\w+)\.delete\(&?(\w+)\)',
            r'// Converted: \1.delete() -> bpf_map_delete_elem()\nbpf_map_delete_elem(&\1, &\2)',
            content
        )

        return content

    def convert_license_and_version(self, content):
        """Add license and other required metadata"""
        # Add license if not present
        if 'char LICENSE[]' not in content and 'SEC("license")' not in content:
            content += '\n\n// Added: libbpf license requirement\nchar LICENSE[] SEC("license") = "GPL";\n'

        # Add version if not present
        if '__u32 _version' not in content:
            content += '// Added: libbpf version requirement\n__u32 _version SEC("version") = 1;\n'

        return content

    def process_file(self, input_file):
        """Process a single BPF source file"""
        print(f"Processing: {input_file}")

        try:
            with open(input_file, 'r') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {input_file}: {e}")
            return False

        # Store original content for analysis
        original_content = content

        # Step 1: Convert headers
        content = self.convert_headers(content)

        # Step 2: Extract and convert BCC table definitions
        bcc_table_pattern = r'BPF_TABLE(?:_SHARED)?\([^)]+\);|BPF_HASH\([^)]+\);|BPF_ARRAY\([^)]+\);|BPF_PERCPU_HASH\([^)]+\);|BPF_PERCPU_ARRAY\([^)]+\);|BPF_F_TABLE\([^)]+\);'

        # Find all table definitions with more context to preserve whitespace
        def extract_table_with_context(match):
            start = match.start()
            end = match.end()
            # Get some context around the match
            line_start = content.rfind('\n', 0, start) + 1
            line_end = content.find('\n', end)
            if line_end == -1:
                line_end = len(content)
            return content[line_start:line_end]

        bcc_table_matches = list(re.finditer(bcc_table_pattern, content, re.MULTILINE | re.DOTALL))
        bcc_tables = [extract_table_with_context(match) for match in bcc_table_matches]

        # Note: We will replace BCC table definitions in place later to preserve conditional compilation

        # Convert to libbpf maps and collect definitions
        map_definitions = []
        for bcc_table in bcc_tables:
            map_info = self.extract_map_info(bcc_table)
            if map_info:
                libbpf_map = self.convert_bcc_table_to_libbpf(map_info)
                map_definitions.append(libbpf_map)

        # Step 3: Convert BCC specific functions
        content = self.convert_bcc_functions(content)

        # Step 4: Convert BCC table usage patterns
        content = self.convert_bcc_table_usage(content)

        # Step 5: Handle conditional compilation directives
        # Convert _INGRESS_LOGIC and _EGRESS_LOGIC conditions
        content = re.sub(r'#if\s+_INGRESS_LOGIC', '// Converted: _INGRESS_LOGIC conditional\n// Ingress logic\n#if 0', content)
        content = re.sub(r'#if\s+_EGRESS_LOGIC', '// Converted: _EGRESS_LOGIC conditional\n// Egress logic\n#if 0', content)
        content = re.sub(r'#endif\s*//.*_LOGIC', '#endif\n// Converted: end of conditional logic', content)

        # Handle _NR_ELEMENTS conditions - keep them but add comments
        content = re.sub(r'(#if\s+_NR_ELEMENTS[^\\n]*)', r'// Preserved conditional compilation\n\1', content)
        content = re.sub(r'(#endif.*_NR_ELEMENTS[^\\n]*)', r'\1\n// End of _NR_ELEMENTS conditional', content)

        # Handle other conditional directives that might be related
        content = re.sub(r'(#if\s+_[A-Z_]+[^\\n]*)', r'// Preserved conditional: \1', content)
        content = re.sub(r'(#endif)', r'\1', content)

        # Step 6: Convert license and version
        content = self.convert_license_and_version(content)

        # Step 7: Replace map definitions in place to preserve conditional compilation
        if map_definitions and bcc_table_matches:
            # Work backwards to avoid position changes
            for i in range(min(len(map_definitions), len(bcc_table_matches)) - 1, -1, -1):
                match = bcc_table_matches[i]

                # Get the line where the original table was
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)

                # Replace the line with the new map definition
                new_map_def = map_definitions[i] + '\n'
                content = content[:line_start] + new_map_def + content[line_end:]

        # Step 8: Final cleanup
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)  # Remove excessive empty lines

        # Write output file
        output_file = self.output_file or (self.output_dir / input_file.name)
        try:
            with open(output_file, 'w') as f:
                f.write(content)
            print(f"Converted: {input_file} -> {output_file}")

            # Print conversion summary
            print(f"  - Found {len(bcc_tables)} BCC table definitions")
            print(f"  - Generated {len(map_definitions)} libbpf map definitions")
            return True

        except Exception as e:
            print(f"Error writing {output_file}: {e}")
            return False

    def process_all_files(self):
        """Process all .c files in the input directory (legacy method)"""
        if not self.input_file:
            print("No input file specified")
            return False

        if not self.input_file.exists():
            print(f"Input file does not exist: {self.input_file}")
            return False

        self.ensure_output_dir()

        print(f"Processing file: {self.input_file}")
        return self.process_file(self.input_file)

    def convert_single_file(self, input_path, output_path=None):
        """Convert a single BCC file to libbpf syntax"""
        self.input_file = Path(input_path)
        self.output_file = Path(output_path) if output_path else None

        return self.process_all_files()

def main():
    """Main function"""
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 bcc_to_libbpf_converter.py <input_file> [output_file]")
        print("")
        print("Arguments:")
        print("  input_file  : Path to the BCC source file to convert")
        print("  output_file : Path to the output libbpf file (optional)")
        print("")
        print("Examples:")
        print("  python3 bcc_to_libbpf_converter.py input.c output.c")
        print("  python3 bcc_to_libbpf_converter.py ../src/datapaths/program.c")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Create converter instance
    converter = BCCToLibbpfConverter(input_file, output_file)

    print("BCC to libbpf Converter (File-to-File)")
    print("=" * 50)
    print(f"Input file: {converter.input_file}")
    print(f"Output file: {converter.output_file or 'auto-generated'}")
    print("=" * 50)

    # Run conversion
    success = converter.convert_single_file(input_file, output_file)

    if success:
        print("\n✅ File converted successfully!")
        print("\nNext steps:")
        print("1. Review the converted file for any syntax issues")
        print("2. Update CMakeLists.txt to use clang instead of BCC")
        print("3. Update user-space code to use libbpf APIs")
        print("4. Test the converted program")
    else:
        print("\n❌ File conversion failed. Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()