# 🛡️ BAKOME Hyperchain Guard – Hyperchain 智能合约安全分析器

**基于 Rust 的静态安全分析工具，专为国产联盟链 Hyperchain 设计。检测 Solidity 智能合约中的重入、整数溢出、权限绕过等常见漏洞，生成 HTML / JSON 报告。**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange)](https://www.rust-lang.org/)
[![Hyperchain](https://img.shields.io/badge/Hyperchain-安全审计-blue)](https://www.hyperchain.cn/)

---

## 🚀 快速开始

### 前置要求
- Rust 1.80+ ([安装指南](https://rustup.rs/))
- 一个 Hyperchain 智能合约的 Solidity 源文件

### 安装与运行

```bash
git clone https://github.com/BAKOME-Hub/BAKOME_Hyperchain_Guard.git
cd BAKOME_Hyperchain_Guard
cargo build --release
./target/release/hyperchain_guard -i 合约.sol -o 报告.html
