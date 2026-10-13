核心原理,让内核连接devpool时信任任何证书,然后重定向devpool和修改钱包

#  用法:
#     python patch_win.py <SRBMiner-MULTI.exe路径> --proxy 127.0.0.1:1080 --pool xxx --wallet xxx ...


注意,建议至少准备两台机器增加成功率,正在内网另一个机器部署socks5蜜罐服务器,因为内核如果通过socks5连不上,就会尝试直连devpool绕过socks5,无法重定向devpool和修改钱包

在矿工机器(注意是矿工机器而不是蜜罐服务器机器)
New-NetFirewallRule -DisplayName "Block-Out-3360-5660-8049" `
  -Direction Outbound -Protocol TCP -RemotePort 3360,5660,8049 -Action Block
这样内核直连devpool的行为会被阻止,导致只能通过socks5






删除规则复原：
Remove-NetFirewallRule -DisplayName "Block-Out-3360-5660-8049"
