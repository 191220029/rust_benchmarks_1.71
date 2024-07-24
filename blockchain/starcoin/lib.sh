#!/bin/bash

# 查找当前目录及其子目录中的所有Cargo.toml文件
find . -name "Cargo.toml" | while read -r file; do
    # 在文件末尾添加[lib]\ndoctest = false\n
    echo "\n[lib]\ndoctest = false" >> "$file"
done
