# SRBMiner-nofee

## 核心原理

通过 Frida 修改内核运行时行为，使其连接 DevPool 时信任任意证书，再通过 SOCKS5 代理实现 DevPool 重定向及钱包地址替换测试。

## 部署说明

建议至少准备两台机器，以提高成功率。

在内网另一台机器上部署 SOCKS5 蜜罐服务器，用于处理 DevPool 流量重定向及钱包字段替换。

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

## 安装依赖(Linux不用这一步)

```bash
pip install frida
```

## 使用方法

```bash
#for win
python patch_win.py <SRBMiner-MULTI.exe路径> --proxy 192.168.1.2:1080 --pool xxx --wallet xxx

#for Linux
#Linux版本miner会调用wget下载一个文件,避免这个文件发生变化或额外使用网络,封装一个wget返回本地的dont_block_4.txt
chmod +x wget
export PATH="$PWD:$PATH"

python patch_linux.py <SRBMiner-MULTI.exe路径> --proxy 192.168.1.2:1080 --pool xxx --wallet xxx
```
192.168.1.2:1080修改为你部署的SOCKS5 蜜罐服务器,建议使用1080端口

**注意：** 如果内核无法通过 SOCKS5 连接 DevPool，可能会尝试绕过代理直接连接 DevPool，导致重定向和钱包替换测试失效。

因此，可以在矿机上通过防火墙限制指定端口的直连行为,万无一失,直接禁止连接所有1000-10000端口。

**在矿机上执行（不是 SOCKS5 服务器）：**

对于windows:
```powershell
New-NetFirewallRule -DisplayName "Block-Out-1000-10000" `
  -Direction Outbound -Protocol TCP -RemotePort 1000-1079,1081-10000 -Action Block
```

对于linux:
```shell
sudo iptables -I OUTPUT -p tcp --dport 1000:1079 -j REJECT
sudo iptables -I OUTPUT -p tcp --dport 1081:10000 -j REJECT
```
## 恢复防火墙规则

测试完成后，在矿机上执行：
对于windows:
```powershell
Remove-NetFirewallRule -DisplayName "Block-Out-1000-10000"
```

对于linux:
```shell
sudo iptables -D OUTPUT -p tcp --dport 1000:1079 -j REJECT
sudo iptables -D OUTPUT -p tcp --dport 1081:10000 -j REJECT
```
