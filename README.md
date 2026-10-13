# SRBMiner-nofee

## 核心原理

通过 Frida 修改内核运行时行为，使其连接 DevPool 时信任任意证书，再通过 SOCKS5 代理实现 DevPool 重定向及钱包地址替换测试。

## 安装依赖

```bash
pip install frida
```

## 使用方法

```bash
python patch_win.py <SRBMiner-MULTI.exe路径> --proxy 127.0.0.1:1080 --pool xxx --wallet xxx
```

## 部署说明

建议至少准备两台机器，以提高成功率。

在内网另一台机器上部署 SOCKS5 蜜罐服务器，用于处理 DevPool 流量重定向及钱包字段替换。

**注意：** 如果内核无法通过 SOCKS5 连接 DevPool，可能会尝试绕过代理直接连接 DevPool，导致重定向和钱包替换测试失效。

因此，可以在矿机上通过防火墙限制指定端口的直连行为。

**在矿机上执行（不是 SOCKS5 服务器）：**

```powershell
New-NetFirewallRule -DisplayName "Block-Out-3360-5660-8049" `
  -Direction Outbound -Protocol TCP -RemotePort 3360,5660,8049 -Action Block
```

该规则阻止通过 TCP 直连远程端口 `3360`、`5660`、`8049`，但不保证阻止其他端口或协议的回退连接。

## 网络架构

```text
              上游矿池
                  ▲
                  │
          SOCKS5 蜜罐服务器
        (DevPool 重定向 / 钱包替换)
                  ▲
                  │
          ┌───────┼───────┐
          │       │       │
        矿机1    矿机2    矿机3 ...
```

所有矿机都必须通过 `--proxy` 指定 SOCKS5 服务器的实际 IP 和端口。

## 恢复防火墙规则

测试完成后，在矿机上执行：

```powershell
Remove-NetFirewallRule -DisplayName "Block-Out-3360-5660-8049"
```
