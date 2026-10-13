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

## 安装依赖(仅Win环境需要)

```bash
pip install frida
```

## 使用方法

```bash
#for win
python patch_win.py <SRBMiner-MULTI.exe路径> --proxy 192.168.1.2:1080 --pool xxx --wallet xxx

#python patch_win.py "C:\Users\Administrator\Downloads\SRBMiner-Multi-3-7-5\SRBMiner-MULTI.exe" --disable-cpu --algorithm quantus --pool hk.lproute.com:5660 --wallet ??.?? --proxy 192.168.1.2:1080 --api-enable

#for Linux
#Linux版本miner会调用wget下载一个文件,避免这个文件发生变化或额外使用网络,封装一个wget返回本地的dont_block_4.txt
chmod +x wget
export PATH="$PWD:$PATH"

python patch_linux.py <SRBMiner-MULTI.exe路径> --proxy 192.168.1.2:1080 --pool xxx --wallet xxx
#python3 /root/patch_linux.py /root/SRBMiner-Multi-3-7-5/SRBMiner-MULTI -disable-cpu --algorithm quantus --pool hk.lproute.com:5660 --wallet ??.?? --proxy 192.168.1.2:1080 --api-enable
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



运行蜜罐服务器:

```shell
npm i
npm start
```




# SRBMiner-nofee

## Core Principle

Use Frida to modify the runtime behavior of the miner core so that it trusts any certificate when connecting to DevPool; then use a SOCKS5 proxy to implement DevPool redirection and wallet address replacement testing.

## Deployment Notes

It is recommended to prepare at least two machines to increase the success rate.  
Deploy a SOCKS5 honeypot server on another machine in the internal network, to handle DevPool traffic redirection and wallet field replacement.

## Network Architecture

```text
Upstream Mining Pool
▲
│
SOCKS5 honeypot server
(DevPool redirection / wallet replacement)
▲
│
┌───────┼───────┐
│       │       │
Rig 1    Rig 2    Rig 3 ...
```

All mining rigs must specify the actual IP and port of the SOCKS5 server via `--proxy`.

## Install Dependencies (Windows only)

```bash
pip install frida
```

## Usage

```bash
# for Windows
python patch_win.py <SRBMiner-MULTI.exe path> --proxy 192.168.1.2:1080 --pool xxx --wallet xxx
# for Linux
# The Linux version of the miner calls wget to download a file; to prevent the file from changing or causing extra network usage, wrap a wget that returns the local dont_block_4.txt
chmod +x wget
export PATH="$PWD:$PATH"
python patch_linux.py <SRBMiner-MULTI.exe path> --proxy 192.168.1.2:1080 --pool xxx --wallet xxx
```

Replace 192.168.1.2:1080 with the SOCKS5 honeypot server you deployed; using port 1080 is recommended.  
**Note:** If the miner core cannot connect to DevPool through SOCKS5, it may attempt to bypass the proxy and connect to DevPool directly, causing the redirection and wallet replacement test to fail.  
Therefore, you can restrict direct connections on specified ports via a firewall on the mining rigs. To be absolutely safe, simply block connections to all ports 1000-10000.  
**Run the following on the mining rigs (not on the SOCKS5 server):**  
For Windows:

```powershell
New-NetFirewallRule -DisplayName "Block-Out-1000-10000" `
-Direction Outbound -Protocol TCP -RemotePort 1000-1079,1081-10000 -Action Block
```

For Linux:

```shell
sudo iptables -I OUTPUT -p tcp --dport 1000:1079 -j REJECT
sudo iptables -I OUTPUT -p tcp --dport 1081:10000 -j REJECT
```

## Restoring Firewall Rules

After testing is complete, run the following on the mining rigs:  
For Windows:

```powershell
Remove-NetFirewallRule -DisplayName "Block-Out-1000-10000"
```

For Linux:

```shell
sudo iptables -D OUTPUT -p tcp --dport 1000:1079 -j REJECT
sudo iptables -D OUTPUT -p tcp --dport 1081:10000 -j REJECT
```

