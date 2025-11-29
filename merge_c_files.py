#!/usr/bin/env python3
"""
合并 XDP enterprise 目录下的所有 .c 文件
将 BPF_TABLE("extern", ...) 转换为 BPF_ARRAY(...)
"""

import os
import re
import glob
from pathlib import Path

def convert_bpf_table_to_array(content):
    """
    将 BPF_TABLE("extern", key_type, value_type, name, size) 转换为 BPF_ARRAY(name, value_type, size)
    """
    # 匹配 BPF_TABLE("extern", ...) 的正则表达式
    pattern = r'BPF_TABLE\(\s*"extern"\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)'

    def replace_func(match):
        # match.group(1) = key_type
        # match.group(2) = value_type
        # match.group(3) = name
        # match.group(4) = size
        name = match.group(3).strip()
        value_type = match.group(2).strip()
        size = match.group(4).strip()

        return f'BPF_ARRAY({name}, {value_type}, {size})'

    return re.sub(pattern, replace_func, content)

def merge_c_files(source_dir, output_file):
    """
    合并目录下所有 .c 文件到一个文件中
    """
    source_path = Path(source_dir)

    # 获取所有 .c 文件并排序
    c_files = sorted(source_path.glob("*.c"))

    if not c_files:
        print(f"在目录 {source_dir} 中没有找到 .c 文件")
        return

    print(f"找到 {len(c_files)} 个 .c 文件:")
    for file in c_files:
        print(f"  - {file.name}")

    with open(output_file, 'w', encoding='utf-8') as outfile:
        for c_file in c_files:
            print(f"处理文件: {c_file.name}")

            # 读取文件内容
            with open(c_file, 'r', encoding='utf-8') as infile:
                content = infile.read()

            # 转换 BPF_TABLE 到 BPF_ARRAY
            converted_content = convert_bpf_table_to_array(content)

            # 写入分隔符和文件名
            filename_line = f"==================== {c_file.name} ===================="
            outfile.write(filename_line + "\n")

            # 写入转换后的内容
            outfile.write(converted_content)
            outfile.write("\n\n")

    print(f"合并完成！输出文件: {output_file}")

def main():
    # 设置源目录和输出文件
    source_directory = "/home/k-haki/Lab/vector-bpf/bpf-iptables/xdp_enterprise"
    output_filename = "merged_xdp_enterprise.c"

    # 检查源目录是否存在
    if not os.path.exists(source_directory):
        print(f"错误: 源目录 {source_directory} 不存在")
        return

    if not os.path.isdir(source_directory):
        print(f"错误: {source_directory} 不是一个目录")
        return

    # 合并文件
    merge_c_files(source_directory, output_filename)

    print("\n转换统计:")
    print("- 所有 BPF_TABLE('extern', ...) 已转换为 BPF_ARRAY(...)")
    print("- 文件间使用 '==================== filename ==================== ' 分隔")
    print(f"- 输出文件: {output_filename}")

if __name__ == "__main__":
    main()