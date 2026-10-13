#!/usr/bin/env python3
# sg.py —— 一键启动（Linux）：<矿工exe> [矿工原始参数...]（全部透传）

#    5. Ctrl+C 一起退出
#
#  用法:
#     python3 sg.py <SRBMiner路径> --proxy <代理> --pool <池> --wallet <钱包> ...
#     例: python3 sg.py /root/srb/SRBMiner-MULTI375 --disable-cpu --algorithm quantus \
#            --pool hk.lproute.com:5660 --wallet qzk...3080 --proxy 192.168.1.6:1191 --api-enable
import sys, os, time, subprocess, socket, ssl, signal

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ---- 矿工内存里的 devpool pin（原始值，替换掉它们）----
REAL_PINS = [
    bytes.fromhex("bd3a865abeed8323371c2cdf489d116686d34d7ec250c320ce426a6c1a6f442b"),
    bytes.fromhex("bfdb1716f350202f9b2e57811b9af14949ed2f9011441f0b334b71419cb5d74b"),
    bytes.fromhex("7747a10d0c5a539214bf850759722d40aa9d27c6a7a99725417728223c05fe69"),
    bytes.fromhex("b9bc7fe6e7a89774f63bc6322c6ce8a89e562e6721baa704962f293cc592562a"),
]

# 热点兜底锚点（pin 还没加载时用）
ANCHORS = (b"luckypool", b"kryptex")
SHA_ANCHOR_WINDOW = 4096
MAX_HOT_SIZE = 4 * 1024 * 1024
RECALC_EVERY = 20.0
COMM_PREFIX = b"SRBMiner"


def ts():
    return time.strftime("%T")


def parse_proxy(args):
    for i, a in enumerate(args):
        if a == "--proxy" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("--proxy="):
            return a.split("=", 1)[1]
    return None


def probe_spki(proxy):
    """★ 自动探测：经 SOCKS5 连代理，取它出示的证书 SPKI（纯 Python 解析 DER）"""
    import spki_util
    host, port = proxy.rsplit(":", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, int(port)), timeout=8)
    raw.sendall(bytes([5, 1, 0]))
    if raw.recv(2) != bytes([5, 0]):
        raise RuntimeError("SOCKS5 方法协商失败")
    th = b"193.70.33.43"
    raw.sendall(bytes([5, 1, 0, 3, len(th)]) + th + (3360).to_bytes(2, "big"))
    rep = raw.recv(10)
    if rep[:2] != bytes([5, 0]):
        raise RuntimeError("SOCKS5 CONNECT 被拒: " + rep[:2].hex())
    tls = ctx.wrap_socket(raw, server_hostname="x")
    spki = spki_util.spki_from_peer_cert(tls)
    tls.close()
    return spki


def wregions(pid):
    """私有可写内存段（rw-p），跳过共享段和超大段"""
    out = []
    try:
        for line in open(f"/proc/{pid}/maps"):
            p = line.split()
            if len(p) < 2 or 'w' not in p[1]:
                continue
            if 'p' not in p[1]:
                continue
            a, b = p[0].split('-')
            lo, hi = int(a, 16), int(b, 16)
            size = hi - lo
            if size > 64 * 1024 * 1024:
                continue
            out.append((lo, hi, size))
    except Exception:
        pass
    return out


def calc_hot(pid, mine_sha):
    """① 含 pin 值的小窗口当热点  ② 兜底用字符串锚点"""
    exact, fallback = [], []
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except Exception:
        return [], []
    try:
        for lo, hi, size in wregions(pid):
            try:
                mem.seek(lo)
                d = mem.read(size)
            except Exception:
                continue
            for pat in REAL_PINS + [mine_sha]:
                i = d.find(pat)
                while i >= 0:
                    w_lo = lo + max(0, i - SHA_ANCHOR_WINDOW)
                    w_hi = lo + min(size, i + len(pat) + SHA_ANCHOR_WINDOW)
                    exact.append((w_lo, w_hi))
                    if len(exact) >= 64:
                        break
                    i = d.find(pat, i + 1)
            if size <= MAX_HOT_SIZE and any(a in d for a in ANCHORS):
                fallback.append((lo, hi))
    finally:
        try:
            mem.close()
        except Exception:
            pass

    def merge(lst):
        lst = sorted(set(lst))
        out = []
        for lo, hi in lst:
            if out and lo <= out[-1][1]:
                out[-1] = (out[-1][0], max(out[-1][1], hi))
            else:
                out.append((lo, hi))
        return out
    return merge(exact), merge(fallback)


def do_round(pid, hot, mine_sha):
    """在热点段里把所有 REAL_PINS 改写成 mine_sha"""
    n = 0
    if not hot:
        return 0
    try:
        mem = open(f"/proc/{pid}/mem", "r+b", buffering=0)
    except Exception:
        return 0
    try:
        for lo, hi in hot:
            try:
                mem.seek(lo)
                d = mem.read(hi - lo)
            except Exception:
                continue
            for pat in REAL_PINS:
                j = d.find(pat)
                while j >= 0:
                    try:
                        mem.seek(lo + j)
                        mem.write(mine_sha)
                        n += 1
                    except Exception:
                        pass
                    j = d.find(pat, j + 1)
    finally:
        try:
            mem.close()
        except Exception:
            pass
    return n


def find_miner():
    """按 comm 前缀找矿工 pid（排除僵尸）"""
    try:
        out = subprocess.run(
            "ps -eo pid,stat,comm --no-headers 2>/dev/null", shell=True,
            capture_output=True).stdout.decode()
        for line in out.splitlines():
            p = line.split(None, 2)
            if len(p) < 3:
                continue
            pid, stat, comm = p
            if 'Z' in stat:
                continue
            if comm.encode().startswith(COMM_PREFIX):
                return int(pid)
    except Exception:
        pass
    return None


def main():
    if len(sys.argv) < 2:
        print("用法: python3 sg.py <SRBMiner路径> [矿工原始参数...]")
        print()
        print("例:   python3 sg.py /root/srb/SRBMiner-MULTI375 \\")
        print("          --proxy 192.168.1.6:1191 --pool hk.lproute.com:5660 --wallet qzk...3080")
        return 1

    exe = sys.argv[1]
    miner_args = sys.argv[2:]

    if not os.path.isfile(exe):
        print("[X] 找不到 exe: %s" % exe)
        return 1

    print("=" * 60)
    print("启动矿工 + pin guard (Linux)")
    print("=" * 60)
    print("  exe   : %s" % exe)
    print("  参数  : %s" % (" ".join(miner_args) if miner_args else "(无)"))

    proxy = parse_proxy(miner_args)
    if not proxy:
        print("  [X] 参数里没有 --proxy，无法自动探测证书 SPKI")
        return 1

    # ★ 自动探测替换目标
    try:
        mine_hex = probe_spki(proxy)
        if not mine_hex or len(mine_hex) != 64:
            raise ValueError("SPKI 长度异常: %r" % (mine_hex,))
        mine_sha = bytes.fromhex(mine_hex)
        print("  替换目标(%s): %s" % (proxy, mine_hex))
    except Exception as e:
        print("  [X] 探测 %s 证书 SPKI 失败: %s %s" % (proxy, type(e).__name__, e))
        print("      —— 请确认代理在运行")
        return 1
    print("  pin 表: %d 个" % len(REAL_PINS))

    exe_dir = os.path.dirname(os.path.abspath(exe))

    # ---- ★ 复刻 st1.sh 的启动配方（实测缺了会触发矿工反篡改：打印 NAUGHTY0 自杀）----
    # 1) lact GPU profile：quantus→qtc，pearlhash→prl
    algo = None
    for i, a in enumerate(miner_args):
        if a == "--algorithm" and i + 1 < len(miner_args):
            algo = miner_args[i + 1]
        elif a.startswith("--algorithm="):
            algo = a.split("=", 1)[1]
    profile = {"quantus": "qtc", "pearlhash": "prl"}.get(algo)
    if profile:
        try:
            r = subprocess.run(["lact", "cli", "profile", "set", profile],
                               capture_output=True, timeout=15)
            print("  lact profile set %s -> rc=%d" % (profile, r.returncode))
        except Exception as e:
            print("  [warn] lact profile 设置失败: %s（继续）" % e)

    # 2) PATH 前置 offline-bin
    env = os.environ.copy()
    obin = os.path.join(exe_dir, "offline-bin")
    if os.path.isdir(obin):
        env["PATH"] = obin + ":" + env.get("PATH", "")
        print("  PATH 前置: %s" % obin)

    print()

    # 3) setsid 启动 + 输出追加到 run_out.log（与 st1.sh 一致）
    logf = open(os.path.join(exe_dir, "run_out.log"), "ab")
    p = subprocess.Popen([exe] + miner_args, cwd=exe_dir, env=env,
                         stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                         start_new_session=True)
    print("  矿工已启动 pid=%d（setsid，输出 -> run_out.log）" % p.pid)

    def cleanup(signum=None, frame=None):
        print("\n  退出中...")
        try:
            p.terminate()
            p.wait(timeout=8)
        except Exception:
            try:
                subprocess.run(["kill", "-9", str(p.pid)], capture_output=True)
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # 等 pin 加载
    print("  等待 pin 加载（8 秒）...")
    time.sleep(8)

    # 存活检查：矿工若触发反篡改会立刻退出（NAUGHTY0）
    if not os.path.exists("/proc/%d/comm" % p.pid):
        print("  [X] 矿工启动后已退出！请看 %s/run_out.log 末尾" % exe_dir)
        return 1

    pid = p.pid
    duration = 7200.0
    interval = 1.0
    print("[%s] guard 启动 pid=%d 时长=%.0fs 间隔=%.1fs" % (ts(), pid, duration, interval), flush=True)

    hot_exact, hot_fb = calc_hot(pid, mine_sha)
    hot = hot_exact or hot_fb
    kb = sum(h - l for l, h in hot) // 1024
    print("[%s] 热点段 %d 个 共 %d KB  (exact=%d fallback=%d)"
          % (ts(), len(hot), kb, len(hot_exact), len(hot_fb)), flush=True)

    t0 = time.time()
    last_calc = time.time()
    rounds = 0
    total = 0

    while time.time() - t0 < duration:
        comm = None
        try:
            comm = open("/proc/%d/comm" % pid).read().strip().encode()
        except Exception:
            comm = None
        if not (comm and comm.startswith(COMM_PREFIX)):
            print("[%s] 目标 %d 消失/易主，跟随新矿工..." % (ts(), pid), flush=True)
            np = None
            for _ in range(60):          # 最多等 60 秒
                time.sleep(1)
                np = find_miner()
                if np:
                    break
            if not np:
                print("[%s] 未找到新矿工，退出" % ts(), flush=True)
                break
            pid = np
            time.sleep(6)
            hot_exact, hot_fb = calc_hot(pid, mine_sha)
            hot = hot_exact or hot_fb
            print("[%s] 跟随 pid=%d，热点段 %d 个" % (ts(), pid, len(hot)), flush=True)
            last_calc = time.time()

        n = do_round(pid, hot, mine_sha)
        total += n
        rounds += 1
        if n:
            print("[%s] [%5.1fs] 改写 %d 处（累计 %d）" % (ts(), time.time() - t0, n, total), flush=True)

        if time.time() - last_calc > RECALC_EVERY:
            hot_exact, hot_fb = calc_hot(pid, mine_sha)
            hot = hot_exact or hot_fb
            last_calc = time.time()

        time.sleep(interval)

    print("[%s] 结束：%d 轮，累计改写 %d 处" % (ts(), rounds, total), flush=True)
    try:
        p.wait(timeout=3)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
