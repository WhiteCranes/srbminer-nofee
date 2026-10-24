#!/usr/bin/env python3
# sg.py —— 一键启动（Linux）：<矿工exe> [矿工原始参数...]（全部透传）
#
#   1. setsid 启动矿工，并给它一个 pty：矿工每行输出由父进程读出来立即 print 到控制台
#      （不再依赖继承 fd，管你是 ssh 单条命令、管道还是 nohup，都能实时看到）
#   2. 经 SOCKS5 探测代理出示的证书 SPKI，作为内存 pin 的替换目标
#   3. 在目标进程的私有可写内存段里滚动替换 devpool pin
#   4. ★ 守护模式：不设时长上限，一直守着。矿工崩溃/退出后，用同样的 exe
#      + 同样的参数立即重新拉起一个新矿工（不去 ps 里找别的进程，避免跟到无关的矿工）
#   4b. ★ 假死看门狗：进程还在但连续 STALL_TIMEOUT 秒没输出 = 假死（GPU 卡住/连接线程死掉），
#      强杀后重新拉起。判活看「有没有动静」，不看 poll() —— 假死时 poll() 永远是 None
#   5. 只有 Ctrl+C / SIGTERM（或达到 MAX_RESTARTS 上限）才整体退出
#
#  用法:
#     python3 sg.py <SRBMiner路径> --proxy <代理> --pool <池> --wallet <钱包> ...
#     例: python3 sg.py /root/srb/SRBMiner-MULTI375 --disable-cpu --algorithm quantus \
#            --pool hk.lproute.com:5660 --wallet qzk...3080 --proxy 192.168.1.6:1191 --api-enable
import sys, os, time, subprocess, socket, ssl, signal, threading

try:                                  # pty 只有类 Unix 有，缺了就自动降级为继承控制台
    import pty, fcntl, termios
except ImportError:                   # pragma: no cover
    pty = None

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

# ---- 重启策略 ----
PIN_WAIT = 8.0            # 每次启动后等 pin 加载的秒数
RESTART_DELAY = 3.0       # 重启基础间隔（秒）
RESTART_DELAY_MAX = 60.0  # 快速崩溃时的最大退避
FAST_CRASH = 15.0         # 存活时间小于该值 -> 判为快速崩溃，退避递增
MAX_RESTARTS = 0          # 0 = 不限次数（守护模式默认永不放弃）
REPROBE_ON_RESTART = True # 重启前顺手重探一次代理证书（失败则沿用旧值）

# ---- 守护策略 ----
IGNORE_SIGHUP = True      # SSH 掉线 / 终端关闭时不跟着退出（建议再配 nohup 或 tmux）
STATUS_EVERY = 300.0      # 心跳日志间隔（秒），0 = 不打心跳

# ---- 假死检测（比「进程还在」更准）----
# 进程活着但不再打印 = 假死（GPU 挂了/驱动卡住/连接线程死了），进程号还挂着但不出活。
# 连续多久收不到矿工任何输出就判定假死、杀掉重开。0 = 关闭检测。
# 取值要明显大于矿工正常输出的最大间隔（正常每 20~40 秒有 Job received，统计块约 2.5 分钟）
def _envf(name, default):
    try:
        return float(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


STALL_TIMEOUT = _envf("SG_STALL_TIMEOUT", 240.0)  # 可用环境变量临时调，如 SG_STALL_TIMEOUT=180
STALL_MIN_AGE = 60.0      # 启动后多少秒内不做假死判定（留给它初始化/连池/编译内核）

# ---- 矿工输出 ----
# True  : 用 pty 给矿工一个真终端，父进程逐行读出来 print —— 保证「一有输出就看得见」
#         （矿工看到 isatty(1)=True，会走行缓冲，颜色/进度条也正常）
# False : 直接让矿工继承当前 stdout（只在本地真终端里跑时才可靠）
USE_PTY = True

# 当前矿工句柄（cleanup / 重启共用）
_CUR = {"proc": None, "pty_fd": None, "reader": None}

# 矿工最后一次吐出字节的时刻 / 累计字节数（假死检测用）
_LAST_OUT = {"t": time.time(), "n": 0}

_OUT_LOCK = threading.Lock()          # 父进程 print 与矿工输出搬运线程共用，防止串行


def ts():
    return time.strftime("%T")


def _emit(data):
    """把原始字节直接写到当前 stdout 并立刻 flush（保留矿工的 ANSI 颜色）"""
    with _OUT_LOCK:
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            return
        except (AttributeError, OSError, ValueError):
            pass
        # 极少数情况下 stdout 被替换成没有 .buffer 的对象，退化成文本写
        try:
            sys.stdout.write(data.decode("utf-8", "replace"))
            sys.stdout.flush()
        except (OSError, ValueError):
            pass


def say(msg):
    """guard 自己的输出：立即 flush；终端被关掉也不要因此把守护进程带崩"""
    with _OUT_LOCK:
        try:
            sys.stdout.write(msg + "\n")
            sys.stdout.flush()
        except (OSError, ValueError):
            pass


def pump_output(fd, tag="miner"):
    """把 pty 里的矿工输出逐行搬到控制台；EOF / EIO（子进程退出）就收工"""
    buf = b""
    while True:
        try:
            chunk = os.read(fd, 8192)
        except OSError:               # pty 从端全关时 Linux 抛 EIO，正常收场
            break
        if not chunk:
            break
        # ★ 记下“最后一次出声音”的时刻：假死检测的唯一依据
        _LAST_OUT["t"] = time.time()
        _LAST_OUT["n"] += len(chunk)
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            _emit(line.rstrip(b"\r") + b"\n")
    if buf:
        _emit(buf)
    try:
        os.close(fd)
    except OSError:
        pass
    if _CUR.get("pty_fd") == fd:
        _CUR["pty_fd"] = None


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


# ---------------- 进程管理：启动 / 回收 / 重启 ----------------

def _copy_winsize(fd):
    """把当前终端窗口尺寸抄给 pty，免得矿工读到 0x0 后把输出排版搞乱"""
    try:
        ws = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, ws)
    except Exception:
        pass


def close_pty():
    """收掉输出搬运线程与 pty 主端（矿工已退出后调用）"""
    t = _CUR.get("reader")
    if t is not None and t.is_alive():
        t.join(timeout=1.5)            # 子进程没了 -> read 收到 EIO -> 线程自然收尾
    fd = _CUR.get("pty_fd")
    if fd is not None and (t is None or not t.is_alive()):
        try:
            os.close(fd)
        except OSError:
            pass
        _CUR["pty_fd"] = None
    _CUR["reader"] = None


def launch(exe, miner_args, exe_dir):
    """启动矿工：优先给矿工一个真 pty，输出由 pump_output 实时 print 到控制台"""
    argv = [exe] + miner_args
    say("\n%s\n===== [%s] 启动矿工：%s\n%s"
        % ("-" * 60, ts(), " ".join(argv), "-" * 60))

    # 新实例起跑：假死计时从这一刻重新算，别被上一个实例的时间戳带偏
    _LAST_OUT["t"] = time.time()
    _LAST_OUT["n"] = 0

    if USE_PTY and pty is not None:
        master = slave = None
        try:
            master, slave = pty.openpty()
            _copy_winsize(master)
            p = subprocess.Popen(argv, cwd=exe_dir, env=os.environ.copy(),
                                 stdin=slave, stdout=slave, stderr=slave,
                                 start_new_session=True, close_fds=True)
            os.close(slave)            # 父进程只保留主端
            _CUR["proc"] = p
            _CUR["pty_fd"] = master
            t = threading.Thread(target=pump_output, args=(master,),
                                 name="miner-out", daemon=True)
            t.start()
            _CUR["reader"] = t
            return p
        except Exception as e:
            say("  [!] pty 启动失败（%s: %s），回退到继承控制台"
                % (type(e).__name__, e))
            for fd in (slave, master):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    # 回退：直接继承当前 stdout/stderr
    p = subprocess.Popen(argv, cwd=exe_dir, env=os.environ.copy(),
                         stdout=None, stderr=None, stdin=subprocess.DEVNULL,
                         start_new_session=True)
    _CUR["proc"] = p
    _CUR["pty_fd"] = None
    _CUR["reader"] = None
    return p


def kill_miner(p=None, sig=signal.SIGTERM, wait=8.0):
    """杀掉整个进程组并回收（僵尸）；p 已退出则只做回收"""
    p = p if p is not None else _CUR.get("proc")
    if p is None:
        return
    if p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), sig)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass
        try:
            p.wait(timeout=wait)
        except Exception:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
            try:
                p.wait(timeout=3)
            except Exception:
                pass
    else:
        try:
            p.wait(timeout=1)          # 回收僵死子进程
        except Exception:
            pass
    if p is _CUR.get("proc"):
        close_pty()                    # 输出搬运线程 + pty 主端一起收掉


def stall_seconds(start_at):
    """假死判定：返回「已静默秒数」，不该判假死时返回 None

    - 关闭检测 / 没走 pty（观测不到输出）/ 还在启动宽限期 -> None
    - 静默超过 STALL_TIMEOUT -> 返回静默时长，由调用方杀掉重开
    """
    if STALL_TIMEOUT <= 0 or _CUR.get("pty_fd") is None:
        return None
    rd = _CUR.get("reader")
    if rd is None or not rd.is_alive():
        return None                    # 观测线程没了 -> 判断不了，别误杀
    if time.time() - start_at <= STALL_MIN_AGE:
        return None
    idle = time.time() - _LAST_OUT["t"]
    return idle if idle > STALL_TIMEOUT else None


def proc_alive(p):
    """还活着且 comm 仍是矿工前缀"""
    if p is None or p.poll() is not None:
        return False
    try:
        comm = open("/proc/%d/comm" % p.pid).read().strip().encode()
    except Exception:
        return False
    return comm.startswith(COMM_PREFIX)


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
    print("  日志  : 矿工输出直连控制台（不再写 run_out.log）")

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
    if STALL_TIMEOUT > 0 and USE_PTY and pty is not None:
        print("  假死检测: %.0f 秒没有任何输出 -> 强杀重开（SG_STALL_TIMEOUT 可调）" % STALL_TIMEOUT)
    else:
        print("  假死检测: 关（未启用 pty，观测不到输出节奏）")

    exe_dir = os.path.dirname(os.path.abspath(exe))

    def spawn():
        """启动矿工 -> 等 pin 加载 -> 算热点段；起不来返回 None（不抛异常，守护继续重试）"""
        try:
            p = launch(exe, miner_args, exe_dir)
        except Exception as e:
            say("[%s] [X] 启动矿工失败：%s %s" % (ts(), type(e).__name__, e))
            return None
        say("[%s] 矿工已启动 pid=%d（setsid，输出直连控制台）" % (ts(), p.pid))
        time.sleep(PIN_WAIT)
        if p.poll() is not None:
            say("[%s] [X] 矿工 pid=%d 启动后立即退出 rc=%s（原因见上方控制台输出）"
                % (ts(), p.pid, p.returncode))
            return None
        he, hf = calc_hot(p.pid, mine_sha)
        hot = he or hf
        kb = sum(h - l for l, h in hot) // 1024
        say("[%s] pid=%d 热点段 %d 个 共 %d KB  (exact=%d fallback=%d)"
            % (ts(), p.pid, len(hot), kb, len(he), len(hf)))
        return hot

    def cleanup(signum=None, frame=None):
        say("\n  收到退出信号，退出中...")
        kill_miner(wait=8.0)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    if IGNORE_SIGHUP and hasattr(signal, "SIGHUP"):
        try:
            # 终端关闭 / SSH 掉线（SIGHUP）不让守护进程跟着死
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        except (OSError, ValueError, AttributeError):
            pass

    start_at = time.time()
    hot = spawn()

    interval = 1.0
    t0 = time.time()
    last_calc = time.time()
    last_status = time.time()
    rounds = 0
    total = 0
    restarts = 0
    fast_fails = 0

    # ★ 守护模式：不设时长上限，一直守着；矿工退出就重新拉起
    while True:
        p = _CUR.get("proc")

        if not proc_alive(p):
            rc = None if p is None else p.poll()
            lived = time.time() - start_at
            if p is None:
                say("[%s] 矿工没起来，准备重启（第 %d 次）" % (ts(), restarts + 1))
            else:
                say("[%s] 矿工 pid=%d 已退出 rc=%s，存活 %.0fs —— 用同样的参数重新拉起（第 %d 次）"
                    % (ts(), p.pid, rc, lived, restarts + 1))
            kill_miner(p)          # 兜底清理残留进程组 + 回收僵尸

            restarts += 1
            if MAX_RESTARTS and restarts > MAX_RESTARTS:
                say("[%s] 重启次数已达上限 %d，退出" % (ts(), MAX_RESTARTS))
                break

            # 退避：连续秒退才越退越久；一旦跑稳过 FAST_CRASH 就清零重来
            if lived >= FAST_CRASH:
                fast_fails = 0
            else:
                fast_fails += 1
            delay = RESTART_DELAY if fast_fails == 0 else min(RESTART_DELAY * fast_fails, RESTART_DELAY_MAX)
            if delay > 0:
                say("  %.0fs 后重启" % delay)
                until = time.time() + delay
                while time.time() < until:
                    time.sleep(min(1.0, max(0.0, until - time.time())))

            # 代理证书可能轮换过：重启前重探一次，失败就沿用旧值
            if REPROBE_ON_RESTART:
                try:
                    h = probe_spki(proxy)
                    if h and len(h) == 64 and h.lower() != mine_sha.hex():
                        mine_sha = bytes.fromhex(h)
                        say("  重探到新的 SPKI: %s" % h)
                except Exception as e:
                    say("  (重探 SPKI 失败，沿用旧值: %s)" % e)

            start_at = time.time()
            hot = spawn()
            last_calc = time.time()
            continue

        # ★ 假死检测：进程还在，但已经很久一个字都没吐出来
        #   （GPU 挂了/驱动卡住/网络线程死掉都是这种表现：进程号还挂着，poll() 永远 False，
        #     只有输出停了。所以这里按“有没有动静”判活，而不是按进程在不在）
        idle = stall_seconds(start_at)
        if idle is not None:
            say("[%s] [X] 矿工 pid=%d 已 %.0f 秒没有任何输出（进程仍在，判定假死）"
                " —— 强杀后重新拉起" % (ts(), p.pid, idle))
            kill_miner(p, sig=signal.SIGKILL, wait=6.0)
            continue

        n = do_round(p.pid, hot, mine_sha)
        total += n
        rounds += 1
        if n:
            say("[%s] [%5.1fs] 改写 %d 处（累计 %d）" % (ts(), time.time() - t0, n, total))

        if time.time() - last_calc > RECALC_EVERY:
            he, hf = calc_hot(p.pid, mine_sha)
            hot = he or hf
            last_calc = time.time()

        if STATUS_EVERY and time.time() - last_status >= STATUS_EVERY:
            say("[%s] 心跳：已守护 %.1f 小时，%d 轮，累计改写 %d 处，重启 %d 次，pid=%d，"
                "最后输出 %.0fs 前（累计 %d KB）"
                % (ts(), (time.time() - t0) / 3600.0, rounds, total, restarts, p.pid,
                   time.time() - _LAST_OUT["t"], _LAST_OUT["n"] // 1024))
            last_status = time.time()

        time.sleep(interval)

    say("[%s] 结束：%d 轮，累计改写 %d 处，重启 %d 次"
        % (ts(), rounds, total, restarts))
    if proc_alive(_CUR.get("proc")):
        say("  矿工 pid=%d 仍在运行（guard 退出，不再改写）" % _CUR["proc"].pid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
