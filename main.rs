//! # BAKOME Hyperchain Guard – 区块链安全分析器 (Hyperchain)
//!
//! 用 Rust 编写，专为国产联盟链 Hyperchain 设计。分析智能合约字节码或源码，
//! 检测常见漏洞（重入、整数溢出、权限绕过、时间戳依赖等），生成 HTML / JSON 报告。

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// 漏洞定义
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize)]
struct Finding {
    pub severity: String,   // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub line: Option<usize>,
}

impl Finding {
    fn new(severity: &str, rule_id: &str, title: &str, description: &str, line: Option<usize>) -> Self {
        Self {
            severity: severity.to_string(),
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            line,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// 分析器核心 (适用于 Hyperchain 的 Solidity 源码或 Yul/Assembly)
// ═══════════════════════════════════════════════════════════════
struct HyperchainAnalyzer {
    source: String,
    findings: Vec<Finding>,
}

impl HyperchainAnalyzer {
    pub fn from_file(path: &PathBuf) -> Result<Self, Box<dyn Error>> {
        let source = fs::read_to_string(path)?;
        Ok(Self {
            source,
            findings: Vec::new(),
        })
    }

    pub fn analyze(&mut self) {
        self.check_reentrancy();
        self.check_integer_overflow();
        self.check_tx_origin();
        self.check_timestamp_dependence();
        self.check_unchecked_calls();
        self.check_selfdestruct();
        self.check_access_control();
        self.check_unchecked_send();
        self.check_assembly_safety();
    }

    /// 1. 重入漏洞
    fn check_reentrancy(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if (line.contains(".call{value:") || line.contains(".call(")) && !line.contains("nonReentrant") {
                self.findings.push(Finding::new(
                    "HIGH",
                    "REENT-01",
                    "可能的重入攻击",
                    "使用 call.value() 或 call() 后未更新状态变量，建议使用 ReentrancyGuard。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 2. 整数溢出 (未使用 SafeMath 且版本 < 0.8)
    fn check_integer_overflow(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if (line.contains('+') || line.contains('-') || line.contains('*')) 
                && !line.contains("SafeMath") && !line.contains("unchecked") 
                && !line.trim_start().starts_with("//") {
                self.findings.push(Finding::new(
                    "MEDIUM",
                    "OVERFLOW-01",
                    "整数溢出风险",
                    "算术运算未使用 SafeMath 或 unchecked。Solidity 0.8+ 默认检查溢出，旧版本需注意。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 3. tx.origin 滥用
    fn check_tx_origin(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if line.contains("tx.origin") && !line.contains("msg.sender") {
                self.findings.push(Finding::new(
                    "MEDIUM",
                    "TXORIGIN-01",
                    "tx.origin 身份验证",
                    "使用 tx.origin 进行权限检查易受钓鱼攻击，建议改用 msg.sender。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 4. 时间戳依赖
    fn check_timestamp_dependence(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if (line.contains("block.timestamp") || line.contains("now")) 
                && (line.contains("if") || line.contains("require")) {
                self.findings.push(Finding::new(
                    "MEDIUM",
                    "TIMESTAMP-01",
                    "区块时间戳依赖",
                    "block.timestamp 可被矿工轻微操纵，不适合用于随机数或关键支付条件。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 5. 未检查的外部调用返回值
    fn check_unchecked_calls(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if line.contains(".call(") && !line.contains("require(") && !line.contains("if") {
                self.findings.push(Finding::new(
                    "HIGH",
                    "CALL-01",
                    "未检查外部调用返回值",
                    "call() 返回值未验证，可能导致状态不一致。建议使用 require(success)。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 6. selfdestruct 自毁
    fn check_selfdestruct(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if line.contains("selfdestruct") || line.contains("suicide") {
                self.findings.push(Finding::new(
                    "CRITICAL",
                    "SELFDEST-01",
                    "合约自毁风险",
                    "selfdestruct 可使合约被销毁，资金可能丢失。强烈建议限制 onlyOwner 并谨慎使用。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 7. 访问控制缺失 (检测 onlyOwner)
    fn check_access_control(&mut self) {
        let has_ownable = self.source.contains("onlyOwner") || self.source.contains("Ownable");
        let sensitive = ["withdraw", "transferOwnership", "setOwner", "kill", "destroy", "mint"];
        for (line_num, line) in self.source.lines().enumerate() {
            for func in &sensitive {
                if line.contains(func) && line.contains("function") && !has_ownable {
                    self.findings.push(Finding::new(
                        "HIGH",
                        "ACCESS-01",
                        &format!("敏感函数 {} 缺少访问控制", func),
                        "只有管理员才能调用的函数未使用 onlyOwner 修饰符，可能被任意账户调用。",
                        Some(line_num + 1),
                    ));
                }
            }
        }
    }

    /// 8. 不安全的 send/transfer (Gas 限制)
    fn check_unchecked_send(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if (line.contains(".send(") || line.contains(".transfer(")) && !line.contains("require") {
                self.findings.push(Finding::new(
                    "MEDIUM",
                    "SEND-01",
                    "不安全的 send/transfer",
                    "send/transfer 固定 Gas 2300，若接收方为合约可能失败。建议使用 call{value:}。",
                    Some(line_num + 1),
                ));
            }
        }
    }

    /// 9. 内联汇编安全检查 (检测 delegatecall, selfdestruct 等)
    fn check_assembly_safety(&mut self) {
        for (line_num, line) in self.source.lines().enumerate() {
            if line.contains("assembly") {
                if line.contains("delegatecall") {
                    self.findings.push(Finding::new(
                        "HIGH",
                        "ASM-01",
                        "不安全的内联汇编 delegatecall",
                        "assembly 中的 delegatecall 需谨慎，确保目标地址可信。",
                        Some(line_num + 1),
                    ));
                }
                if line.contains("selfdestruct") {
                    self.findings.push(Finding::new(
                        "CRITICAL",
                        "ASM-02",
                        "内联汇编中的 selfdestruct",
                        "assembly 内直接使用 selfdestruct 风险极高，避免或严格限制。",
                        Some(line_num + 1),
                    ));
                }
            }
        }
    }

    pub fn get_findings(&self) -> &Vec<Finding> {
        &self.findings
    }
}

// ═══════════════════════════════════════════════════════════════
// 报告生成 (HTML)
// ═══════════════════════════════════════════════════════════════
fn generate_html_report(findings: &[Finding], input_file: &str, output_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    let critical: Vec<_> = findings.iter().filter(|f| f.severity == "CRITICAL").collect();
    let high: Vec<_> = findings.iter().filter(|f| f.severity == "HIGH").collect();
    let medium: Vec<_> = findings.iter().filter(|f| f.severity == "MEDIUM").collect();
    let low: Vec<_> = findings.iter().filter(|f| f.severity == "LOW").collect();

    let rows: String = findings.iter().map(|f| {
        format!(
            r#"<tr class="severity-{}"><td>{}<\/td><td>{}<\/td><td>{}<\/td><td>{}<\/td><td>{}<\/td></td>"#,
            f.severity.to_lowercase(),
            f.severity,
            f.rule_id,
            f.title,
            f.description,
            f.line.map_or("—".to_string(), |l| l.to_string())
        )
    }).collect();

    let html = format!(
        r#"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>BAKOME Hyperchain Guard – 安全分析报告</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f0f2f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; border-radius: 12px; padding: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #1a3e60; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
        .card {{ background: #f8f9fa; border-radius: 12px; padding: 20px; text-align: center; flex: 1; min-width: 120px; }}
        .card .number {{ font-size: 28px; font-weight: bold; }}
        .severity-critical {{ background-color: #dc3545; color: white; }}
        .severity-high {{ background-color: #fd7e14; color: white; }}
        .severity-medium {{ background-color: #ffc107; color: black; }}
        .severity-low {{ background-color: #28a745; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #2c7da0; color: white; }}
        footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #777; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ BAKOME Hyperchain Guard – 安全分析报告</h1>
    <p>分析文件: {} | 生成时间: {}</p>

    <div class="summary">
        <div class="card"><div class="number">{}</div><h3>严重</h3></div>
        <div class="card"><div class="number">{}</div><h3>高危</h3></div>
        <div class="card"><div class="number">{}</div><h3>中等</h3></div>
        <div class="card"><div class="number">{}</div><h3>低危</h3></div>
        <div class="card"><div class="number">{}</div><h3>总计</h3></div>
    </div>

    <h2>📋 漏洞详情</h2>
    <table>
        <thead><tr><th>严重性</th><th>规则 ID</th><th>标题</th><th>描述</th><th>行号</th></tr></thead>
        <tbody>{}</tbody>
    </table>
    <footer>报告由 BAKOME Hyperchain Guard (Rust) 生成 – 仅用于安全研究，不构成投资建议。</footer>
</div>
</body>
</html>
"#,
        input_file,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        critical.len(),
        high.len(),
        medium.len(),
        low.len(),
        findings.len(),
        rows
    );
    fs::write(output_path, html)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════
#[derive(Parser)]
#[command(author, version, about = "BAKOME Hyperchain Guard – Hyperchain 智能合约安全分析器", long_about = None)]
struct Cli {
    /// 输入的 Solidity 合约文件路径
    #[arg(short, long)]
    input: PathBuf,

    /// 输出的 HTML 报告路径 (默认 hyperchain_report.html)
    #[arg(short, long, default_value = "hyperchain_report.html")]
    output: PathBuf,

    /// 可选：输出 JSON 报告
    #[arg(long)]
    json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let mut analyzer = HyperchainAnalyzer::from_file(&cli.input)?;
    analyzer.analyze();
    let findings = analyzer.get_findings();

    generate_html_report(findings, &cli.input.to_string_lossy(), &cli.output)?;

    if let Some(json_path) = cli.json {
        let json_str = serde_json::to_string_pretty(findings)?;
        fs::write(json_path, json_str)?;
    }

    println!("分析完成。发现 {} 个问题。报告已保存至: {}", findings.len(), cli.output.display());
    Ok(())
}
