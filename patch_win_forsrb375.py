#!/usr/bin/env python3
# patch_win.py - 通用启动器：<矿工exe> [矿工原始参数...]（全部透传，无默认值）
#
#  用法:
#     python patch_win.py <SRBMiner-MULTI.exe路径> --proxy 127.0.0.1:1099 --pool xxx --wallet xxx ...
#
#  它会:
#     1. 从透传参数里解析出 --proxy（取代理证书 SPKI 需要它）
#     2. 启动矿工（参数原样透传，不做任何预设/改写）
#     3. attach 注入 pin patch：把内存里的 devpool pin 换成该代理的 SPKI
#     4. 跟随运行，Ctrl+C 退出
#
import subprocess, time, json, sys, os, socket, ssl

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ---- 矿工内置的 qtc devpool 全集（仅用于生成"路标"，与透传参数无关）----
QTC_DEVPOOLS = [
    "51.79.178.47:5660", "82.26.136.177:5660", "51.68.154.53:5660",
    "147.135.37.130:5660", "193.70.33.43:5660", "141.105.71.219:5660",
    "51.79.178.47:3360", "82.26.136.177:3360", "51.68.154.53:3360",
    "147.135.37.130:3360", "193.70.33.43:3360", "141.105.71.219:3360",
    "qtc.kryptex.network:8049", "qtc-eu.kryptex.network:8049",
    "qtc-us.kryptex.network:8049", "qtc-ru.kryptex.network:8049",
]

# 路标：优先具体端点（裸 IP + 具体域名），再泛化兜底
MARKERS = []
for _ep in QTC_DEVPOOLS:
    _h = _ep.rsplit(":", 1)[0]
    if _h[0].isdigit():
        MARKERS.append(_h)
for _ep in QTC_DEVPOOLS:
    _h = _ep.rsplit(":", 1)[0]
    if not _h[0].isdigit():
        MARKERS.append(_h)
MARKERS += [
    "kryptex.network", "lproute.com",
    ":3360", ":1200", ":8048", ":5660", ":8049", ":7048",
]
_seen = set()
MARKERS = [m for m in MARKERS if not (m in _seen or _seen.add(m))]

# 已知的 4 个真实 pin（内存里要替换掉的值）
REAL_PINS = [
    "bd3a865abeed8323371c2cdf489d116686d34d7ec250c320ce426a6c1a6f442b",
    "bfdb1716f350202f9b2e57811b9af14949ed2f9011441f0b334b71419cb5d74b",
    "7747a10d0c5a539214bf850759722d40aa9d27c6a7a99725417728223c05fe69",
    "b9bc7fe6e7a89774f63bc6322c6ce8a89e562e6721baa704962f293cc592562a",
]

SOCKS_REQ = bytes([5, 1, 0])


def parse_proxy(miner_args):
    """从矿工参数里解析 --proxy（支持 --proxy X 和 --proxy=X）"""
    for i, a in enumerate(miner_args):
        if a == "--proxy" and i + 1 < len(miner_args):
            return miner_args[i + 1]
        if a.startswith("--proxy="):
            return a.split("=", 1)[1]
    return None


def proxy_spki(proxy):
    """经 SOCKS5 连代理，取它出示的证书 SPKI SHA-256（纯 Python 解析 DER）"""
    import spki_util
    host, port = proxy.rsplit(":", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, int(port)), timeout=8)
    raw.sendall(SOCKS_REQ)
    if raw.recv(2) != bytes([5, 0]):
        raise RuntimeError("SOCKS5 方法协商失败")
    th = b"193.70.33.43"
    req = bytes([5, 1, 0, 3, len(th)]) + th + (3360).to_bytes(2, "big")
    raw.sendall(req)
    rep = raw.recv(10)
    if rep[:2] != bytes([5, 0]):
        raise RuntimeError("SOCKS5 CONNECT 被拒: " + rep[:2].hex())
    tls = ctx.wrap_socket(raw, server_hostname="x")
    spki = spki_util.spki_from_peer_cert(tls)
    tls.close()
    return spki


JS = r"""
function S(m){ send('' + m); }
var PINS = %PINS%, MINE = %MINE%, MARKERS = %MARKERS%;
var MB = null, patched = {}, hitStat = {};
function h2p(h){var s='';for(var i=0;i<64;i+=2)s+=h.substr(i,2)+' ';return s.trim();}
function hx(s){var o=[];for(var i=0;i<s.length;i++)o.push(('0'+s.charCodeAt(i).toString(16)).slice(-2));return o.join(' ');}

/* 按路标找区域：每个路标各分配名额，避免靠前的路标吃光名额 */
function markerRegions(mks, PER, maxMB){
  var out=[], seen={}, rs=Process.enumerateRanges('r--');
  var maxSize=(maxMB||8)*1024*1024;
  for(var m=0;m<mks.length;m++){
    var cnt=0;
    for(var i=0;i<rs.length&&cnt<PER;i++){
      var r=rs[i];
      if(r.size<2048||r.size>maxSize) continue;
      if(r.protection.indexOf('w')<0) continue;
      if(MB&&r.base.compare(MB)>=0&&r.base.compare(MB.add(0x4000000))<0) continue;
      var k=r.base.toString(); if(seen[k]) continue;
      try{
        if(Memory.scanSync(r.base,r.size,hx(mks[m])).length){
          out.push({base:r.base,size:r.size,marker:mks[m]});
          seen[k]=1; cnt++;
          hitStat[mks[m]]=(hitStat[mks[m]]||0)+1;
        }
      }catch(e){}
    }
  }
  return out;
}

/* 快通道：不用路标，直接在小区域里搜 pin 值 */
function doPatchDirect(tag, maxMB){
  var n=0, maxSize=(maxMB||2)*1024*1024;
  var rs=Process.enumerateRanges('r--');
  for(var i=0;i<rs.length;i++){
    var r=rs[i];
    if(r.size<512||r.size>maxSize) continue;
    if(r.protection.indexOf('w')<0) continue;
    if(MB&&r.base.compare(MB)>=0&&r.base.compare(MB.add(0x4000000))<0) continue;
    for(var p=0;p<PINS.length;p++){
      var hits=[];
      try{ hits=Memory.scanSync(r.base,r.size,h2p(PINS[p])); }catch(e){continue;}
      if(!hits.length) continue;
      hits.forEach(function(h_){
        var a=h_.address, k=a.toString();
        if(patched[k]) return;
        try{ Memory.protect(a,32,'rw-'); a.writeByteArray(MINE); patched[k]=1; n++; }catch(e){}
      });
    }
  }
  if(n) S('[' + tag + '] 直接替换 ' + n + ' 处，累计 ' + Object.keys(patched).length);
  return n;
}

/* 按路标替换 */
function doPatch(tag, mks, per){
  var n=0;
  markerRegions(mks || MARKERS, per || 3, 8).forEach(function(r){
    for(var p=0;p<PINS.length;p++){
      var hits=[];
      try{ hits=Memory.scanSync(r.base,r.size,h2p(PINS[p])); }catch(e){continue;}
      hits.forEach(function(h_){
        var a=h_.address, k=a.toString();
        if(patched[k]) return;
        try{ Memory.protect(a,32,'rw-'); a.writeByteArray(MINE); patched[k]=1; n++; }catch(e){}
      });
    }
  });
  if(n) S('[' + tag + '] 路标替换 ' + n + ' 处，累计 ' + Object.keys(patched).length);
  return n;
}

function dumpHitStat(){
  var ks = Object.keys(hitStat);
  if(!ks.length){ S('路标命中统计: (无)'); return; }
  var total = 0;
  ks.forEach(function(k){ total += hitStat[k]; });
  S('路标命中 ' + ks.length + ' 个（区域共 ' + total + '）');
  ks.sort().forEach(function(k){ S('   ' + k + ' x' + hitStat[k]); });
}

var patchReady = false;
var patchStart = 0;

setTimeout(function(){
  MB = Process.enumerateModules()[0].base;
  patchStart = Date.now();

  /* 阶段1：快通道直接搜 pin，抢时间 */
  var tries=0;
  var t=setInterval(function(){
    tries++;
    var n=doPatchDirect('D'+tries, 2);
    if(n>0||tries>=30){
      clearInterval(t);
      patchReady = true;
      S('快通道命中（累计 ' + Object.keys(patched).length + ' 处，第 ' + tries +
        ' 轮，耗时 ' + (Date.now()-patchStart) + 'ms）');
      /* 阶段2：全量补漏 */
      doPatchDirect('全量直搜', 8);
      doPatch('全量路标', MARKERS, 3);
      S('全量补漏后（累计 ' + Object.keys(patched).length + ' 处）');
      dumpHitStat();
      setInterval(function(){ doPatchDirect('补漏', 8); }, 1000);
    }
  }, 100);

  /* connect 时补一次（不阻塞、不失败连接） */
  var pc=null;
  try{ pc=Module.getExportByName('WS2_32.dll','connect'); }catch(e){}
  if(!pc){ try{ pc=Process.getModuleByName('WS2_32.dll').getExportByName('connect'); }catch(e){} }
  if(pc) Interceptor.attach(pc,{onEnter:function(a){
    try{
      if(a[1].readU16()!==2) return;
      var port=((a[1].add(2).readU8()<<8)|a[1].add(3).readU8())>>>0;
      if(!(port===5660||port===3360||port===1200||port===8048||port===8049||port===7048)) return;
      var n=doPatchDirect('connect', 8);
      if(n) S('  connect 补 ' + n + ' 处');
      if(!patchReady) S('  connect ' + port + '（patch 尚未就绪，已换 ' +
                        Object.keys(patched).length + ' 处）');
    }catch(e){}
  }});
}, 150);
"""


def main():
    if len(sys.argv) < 2:
        print("用法: python start.py <SRBMiner-MULTI.exe路径> [矿工原始参数...]")
        print()
        return 1

    exe = sys.argv[1]
    miner_args = sys.argv[2:]

    if not os.path.isfile(exe):
        print("[X] 找不到 exe: %s" % exe)
        return 1

    print("=" * 62)
    print("启动矿工 + pin patch")
    print("=" * 62)
    print("  exe   : %s" % exe)
    print("  参数  : %s" % (" ".join(miner_args) if miner_args else "(无)"))

    proxy = parse_proxy(miner_args)
    if not proxy:
        print("  [X] 参数里没有 --proxy，无法取代理证书 SPKI，无法打 patch")
        return 1

    mine = None
    try:
        mine = proxy_spki(proxy)
        if not mine or len(mine) != 64:
            raise ValueError("SPKI 长度异常: %r" % (mine,))
        print("  替换目标(%s): %s" % (proxy, mine))
    except Exception as e:
        print("  [X] 取 %s 证书 SPKI 失败: %s %s" % (proxy, type(e).__name__, e))
        return 1

    print("  路标  : %d 个" % len(MARKERS))
    print()
    p = subprocess.Popen([exe] + miner_args, cwd=os.path.dirname(os.path.abspath(exe)))

    import frida
    dev = frida.get_local_device()
    sess = dev.attach(p.pid)
    sc = sess.create_script(
        JS.replace("%PINS%", json.dumps(REAL_PINS))
          .replace("%MINE%", json.dumps([int(mine[i:i+2], 16) for i in range(0, 64, 2)]))
          .replace("%MARKERS%", json.dumps(MARKERS)))
    sc.on("message", lambda m, d: print("  [patch] " + str(m.get("payload"))[:110])
          if m.get("type") == "send" else None)
    sc.load()

    print("  运行中... Ctrl+C 退出\n")
    try:
        p.wait()
    except KeyboardInterrupt:
        print("\n  退出中...")
        p.terminate()
        try:
            p.wait(timeout=6)
        except Exception:
            subprocess.run(["taskkill", "/F", "/PID", str(p.pid)], capture_output=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
