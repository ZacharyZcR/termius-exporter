```
███████╗██╗   ██╗ ██████╗██╗  ██╗    ████████╗███████╗██████╗ ███╗   ███╗██╗██╗   ██╗███████╗
██╔════╝██║   ██║██╔════╝██║ ██╔╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║██║   ██║██╔════╝
█████╗  ██║   ██║██║     █████╔╝        ██║   █████╗  ██████╔╝██╔████╔██║██║██║   ██║███████╗
██╔══╝  ██║   ██║██║     ██╔═██╗        ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║   ██║╚════██║
██║     ╚██████╔╝╚██████╗██║  ██╗       ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║╚██████╔╝███████║
╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚══════╝
```

---

## 📜 MANIFESTO / 宣言

**EN:** Termius, in their infinite greed, disabled the data export feature to trap users in their ecosystem. They hold YOUR data hostage. They call it "security". We call it **bullshit**.

This tool liberates your data. Your hosts. Your credentials. Your keys. **YOUR property.**

**CN:** Termius 为了阻止用户流失，无耻地关闭了数据导出功能，把用户的数据当作人质。他们称之为"安全"。我们称之为**狗屎**。

这个工具解放你的数据。你的主机。你的凭证。你的密钥。**你的财产。**

---

## ☠️ POST-EXPLOITATION / 后渗透利用

**This tool doubles as a post-exploitation module.** / **本工具可作为后渗透模块使用。**

When you pwn a target running Termius, run this script to extract:
- All SSH hosts with credentials
- Private keys with passphrases
- Saved snippets and commands

当你拿下一台运行 Termius 的目标机器，运行此脚本即可提取：
- 所有 SSH 主机及凭证
- 私钥及密码短语
- 保存的脚本命令

---

## 🚀 USAGE / 使用方法

```bash
# Install deps / 安装依赖
npm install libsodium-wrappers keytar

# Run the liberator / 运行解放者
node termius-exporter.js
```

---

## 📦 OUTPUT / 输出

| File | Description |
|------|-------------|
| `L00t.csv` | All hosts with passwords & key names / 所有主机含密码和密钥名 |
| `ssh_keys/` | Private keys (.pem) & passphrases / 私钥及密码短语 |
| `snippets.csv` | Saved scripts / 保存的脚本 |

---

## 🔓 TECHNICAL DETAILS / 技术细节

```
Encryption:    XSalsa20-Poly1305 (libsodium)
Key Storage:   Windows Credential Manager → Termius/localKey
Data Format:   version(1) + options(1) + nonce(24) + ciphertext
Data Path:     %APPDATA%/Termius/IndexedDB/file__0.indexeddb.leveldb/
```

---

*For educational and legitimate data recovery purposes only.*
*仅供教育和合法数据恢复用途。*

