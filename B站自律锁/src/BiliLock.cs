using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace BiliLock
{
    static class Rules
    {
        // hosts 精确域名（hosts 不支持通配符，子域/弹窗靠窗口守卫兜底）
        public static readonly string[] Domains = new string[]
        {
            "bilibili.com", "m.bilibili.com", "api.bilibili.com",
            "app.bilibili.com", "space.bilibili.com", "search.bilibili.com", "t.bilibili.com",
            "message.bilibili.com", "passport.bilibili.com", "sso.bilibili.com", "account.bilibili.com",
            "member.bilibili.com", "link.bilibili.com", "game.bilibili.com", "manga.bilibili.com",
            "show.bilibili.com", "data.bilibili.com", "upos.bilibili.com", "mall.bilibili.com",
            "live.bilibili.com", "api.live.bilibili.com", "broadcast.chat.bilibili.com",
            "bilibili.tv", "api.bilibili.tv",
            "hdslb.com", "i0.hdslb.com", "s1.hdslb.com", "data.hdslb.com",
            "bilivideo.com", "live.bilivideo.com",
            "upos-sz-mirrorcos.bilivideo.com", "upos-sz-mirrorali.bilivideo.com",
            "upos-sz-mirrorhw.bilivideo.com", "upos-sz-mirror08c.bilivideo.com",
            "cn-hk-eq-bcache-01.bilivideo.com",
            "b23.tv", "bili2233.cn", "bili22.cn", "bili33.cn",
            "biliapi.net", "api.biliapi.net", "grpc.biliapi.net", "biliapi.com",
            "biligame.com", "www.biligame.com"
        };

        public const string TitlePattern = @"(?i)(bilibili|哔哩|b23\.tv|hdslb|bilivideo)";
        public const string ProcPattern = @"(?i)(bilibili|哔哩)";
    }

    static class HostsFile
    {
        public const string DefaultPath = @"C:\Windows\System32\drivers\etc\hosts";
        const string BeginMark = "# >>> BiliLock BLOCK BEGIN (managed by BiliLock, do not edit) >>>";
        const string EndMark = "# <<< BiliLock BLOCK END <<<";

        public static string Path_ = DefaultPath;

        public static bool IsEnabled()
        {
            try
            {
                if (!File.Exists(Path_)) return false;
                return File.ReadAllText(Path_).IndexOf(BeginMark, StringComparison.Ordinal) >= 0;
            }
            catch { return false; }
        }

        public static int EnabledCount()
        {
            try
            {
                if (!File.Exists(Path_)) return 0;
                int n = 0; bool inside = false;
                foreach (string line in File.ReadAllLines(Path_))
                {
                    string s = line.Trim();
                    if (s == BeginMark) { inside = true; continue; }
                    if (s == EndMark) { inside = false; continue; }
                    if (inside && s.Length > 0 && !s.StartsWith("#")) n++;
                }
                return n;
            }
            catch { return 0; }
        }

        static string NL { get { return Environment.NewLine; } }

        // 固定格式的封锁块（Restore 靠它做精确反向替换）
        static string BuildBlock()
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string d in Rules.Domains)
            {
                string dd = d.Trim().ToLowerInvariant();
                if (dd.Length == 0) continue;
                set.Add(dd);
                if (!dd.StartsWith("www.")) set.Add("www." + dd);
            }
            List<string> list = new List<string>(set);
            list.Sort(StringComparer.OrdinalIgnoreCase);

            StringBuilder sb = new StringBuilder();
            sb.AppendLine(BeginMark);
            foreach (string d in list) sb.AppendLine("0.0.0.0 " + d);
            sb.AppendLine(EndMark);
            return sb.ToString();
        }

        public static void Apply()
        {
            string original = File.Exists(Path_) ? File.ReadAllText(Path_) : "";
            string bak = Path_ + ".bililock.bak";
            if (!File.Exists(bak)) File.WriteAllText(bak, original, new UTF8Encoding(false));

            Restore(); // 先清旧块，保证幂等

            string head = File.Exists(Path_) ? File.ReadAllText(Path_) : "";
            File.WriteAllText(Path_, head + NL + BuildBlock(), new UTF8Encoding(false));
        }

        public static void Restore()
        {
            if (!File.Exists(Path_)) return;
            string text = File.ReadAllText(Path_);
            string expect = NL + BuildBlock();
            if (text.IndexOf(BeginMark, StringComparison.Ordinal) >= 0 && text.Contains(expect))
            {
                // 精确反向替换：原文件一个字节都不改
                File.WriteAllText(Path_, text.Replace(expect, ""), new UTF8Encoding(false));
                return;
            }
            // 兜底：块被手工动过
            int start = text.IndexOf(BeginMark, StringComparison.Ordinal);
            if (start < 0) return;
            int cut = start;
            while (cut > 0 && (text[cut - 1] == '\r' || text[cut - 1] == '\n')) cut--;
            int end = text.IndexOf(EndMark, start);
            if (end < 0) text = text.Substring(0, cut);
            else
            {
                int tail = end + EndMark.Length;
                while (tail < text.Length && (text[tail] == '\r' || text[tail] == '\n')) tail++;
                text = text.Substring(0, cut) + text.Substring(tail);
            }
            File.WriteAllText(Path_, text, new UTF8Encoding(false));
        }

        public static void FlushDns()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("ipconfig", "/flushdns");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process p = Process.Start(psi);
                if (p != null) p.WaitForExit(5000);
            }
            catch { }
        }
    }

    static class DohPolicy
    {
        static readonly string[,] Keys = new string[,]
        {
            { @"Software\Policies\Microsoft\Edge", "DnsOverHttpsMode" },
            { @"Software\Policies\Google\Chrome", "DnsOverHttpsMode" }
        };

        public static void Disable()
        {
            for (int i = 0; i < Keys.GetLength(0); i++)
            {
                try
                {
                    RegistryKey k = Registry.CurrentUser.CreateSubKey(Keys[i, 0]);
                    if (k != null) { k.SetValue(Keys[i, 1], "off", RegistryValueKind.String); k.Close(); }
                }
                catch { }
            }
        }

        public static void Restore()
        {
            for (int i = 0; i < Keys.GetLength(0); i++)
            {
                try
                {
                    RegistryKey k = Registry.CurrentUser.OpenSubKey(Keys[i, 0], true);
                    if (k != null) { k.DeleteValue(Keys[i, 1], false); k.Close(); }
                }
                catch { }
            }
        }
    }

    // 单实例 + "再点一次主程序就唤出面板"
    static class SingleInstance
    {
        const string MutexName = @"Local\BiliLock.SingleInstance";
        const string EventName = @"Local\BiliLock.ShowPanel";
        static Mutex mtx;
        public static EventWaitHandle ShowEvent;

        public static bool Acquire(bool takeover)
        {
            bool created;
            try
            {
                mtx = new Mutex(true, MutexName, out created);
                if (created) { EnsureEvent(); return true; }
                if (!takeover) { mtx.Dispose(); mtx = null; return false; }
                // 交接：等前一个实例退出后接管
                bool got = false;
                for (int i = 0; i < 20 && !got; i++)
                {
                    try { got = mtx.WaitOne(300); } catch { }
                }
                if (got) { EnsureEvent(); return true; }
                mtx.Dispose(); mtx = null;
                return false;
            }
            catch { return true; }
        }

        static void EnsureEvent()
        {
            try { ShowEvent = EventWaitHandle.OpenExisting(EventName); }
            catch
            {
                try { ShowEvent = new EventWaitHandle(false, EventResetMode.AutoReset, EventName); }
                catch { ShowEvent = null; }
            }
        }

        // 第二个实例：通知已存在的实例把面板亮出来，然后自己退出
        public static void RaiseShow()
        {
            try
            {
                EventWaitHandle e;
                try { e = EventWaitHandle.OpenExisting(EventName); }
                catch { e = new EventWaitHandle(false, EventResetMode.AutoReset, EventName); }
                e.Set();
                e.Close();
            }
            catch { }
        }
    }
    // 自律时段：开始前可取消；进入时段后程序内不可解除
    static class Session
    {
        public static long StartTicks;
        public static long EndTicks;

        public static string Dir
        {
            get
            {
                string d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BiliLock");
                try { if (!Directory.Exists(d)) Directory.CreateDirectory(d); }
                catch { }
                return d;
            }
        }

        static string FilePath { get { return Path.Combine(Dir, "session.txt"); } }

        public static bool Has { get { return EndTicks > 0; } }
        public static bool IsActive { get { return Has && DateTime.Now.Ticks >= StartTicks && DateTime.Now.Ticks < EndTicks; } }
        public static bool IsPending { get { return Has && DateTime.Now.Ticks < StartTicks; } }

        public static void Save(long start, long end)
        {
            StartTicks = start; EndTicks = end;
            try { File.WriteAllText(FilePath, start + Environment.NewLine + end + Environment.NewLine, new UTF8Encoding(false)); }
            catch { }
        }

        public static void Clear()
        {
            StartTicks = 0; EndTicks = 0;
            try { if (File.Exists(FilePath)) File.Delete(FilePath); }
            catch { }
        }

        public static void LoadFromDisk()
        {
            try
            {
                if (Has) return; // 命令行已指定时段时，不被磁盘旧值覆盖
                if (!File.Exists(FilePath)) return;
                string[] lines = File.ReadAllLines(FilePath);
                long s, e;
                if (lines.Length >= 2 && long.TryParse(lines[0], out s) && long.TryParse(lines[1], out e))
                { StartTicks = s; EndTicks = e; }
            }
            catch { }
        }

        public static string Fmt(TimeSpan ts)
        {
            if (ts.TotalMilliseconds < 0) ts = TimeSpan.Zero;
            if (ts.TotalHours >= 1) return string.Format("{0}:{1:00}:{2:00}", (int)ts.TotalHours, ts.Minutes, ts.Seconds);
            return string.Format("{0:00}:{1:00}", ts.Minutes, ts.Seconds);
        }

        public static string RemainText() { return Fmt(TimeSpan.FromTicks(Math.Max(0, EndTicks - DateTime.Now.Ticks))); }
        public static string UntilText() { return Fmt(TimeSpan.FromTicks(Math.Max(0, StartTicks - DateTime.Now.Ticks))); }

        public static string ClockText(long ticks)
        {
            DateTime dt = new DateTime(ticks);
            DateTime now = DateTime.Now;
            return dt.Date == now.Date ? dt.ToString("HH:mm") : dt.ToString("MM-dd HH:mm");
        }
    }

    static class Nat
    {
        public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
        [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
        public const uint WM_CLOSE = 0x0010;
        public const int SW_MINIMIZE = 6;
    }

    class Guard
    {
        public int Closed;
        public int Failed;
        public string LastHit = "";
        readonly Regex titleRe = new Regex(Rules.TitlePattern);
        readonly Regex procRe = new Regex(Rules.ProcPattern);
        readonly int selfPid = Process.GetCurrentProcess().Id;
        public bool MinimizeMode = false;
        public static bool DebugOn = Environment.GetEnvironmentVariable("BILILOCK_DEBUG") == "1";

        static string LogPath
        {
            get
            {
                try { return Path.Combine(Session.Dir, "debug.log"); }
                catch { return Path.Combine(Path.GetTempPath(), "bililock-debug.log"); }
            }
        }

        public static void Dbg(string s)
        {
            if (!DebugOn) return;
            try { File.AppendAllText(LogPath, s + Environment.NewLine, new UTF8Encoding(false)); } catch { }
        }

        public void Scan()
        {
            int visible = 0, matched = 0;
            Nat.EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                try
                {
                    if (!Nat.IsWindowVisible(h)) return true;
                    uint pid;
                    Nat.GetWindowThreadProcessId(h, out pid);
                    if ((int)pid == selfPid) return true;

                    StringBuilder sb = new StringBuilder(512);
                    Nat.GetWindowText(h, sb, sb.Capacity);
                    string title = sb.ToString();
                    if (title.Length == 0) return true;
                    visible++;

                    bool hit = titleRe.IsMatch(title);
                    if (!hit)
                    {
                        try { if (procRe.IsMatch(Process.GetProcessById((int)pid).ProcessName)) hit = true; }
                        catch { }
                    }
                    if (!hit) return true;

                    matched++;
                    if (MinimizeMode) Nat.ShowWindow(h, Nat.SW_MINIMIZE);
                    else
                    {
                        if (Nat.PostMessage(h, Nat.WM_CLOSE, IntPtr.Zero, IntPtr.Zero)) Closed++;
                        else Failed++;
                    }
                    LastHit = title.Length > 40 ? title.Substring(0, 40) : title;
                    Dbg("HIT hwnd=" + h.ToInt64() + " pid=" + pid + " mode=" + (MinimizeMode ? "min" : "close") + " title=" + title);
                }
                catch { }
                return true;
            }, IntPtr.Zero);
            if (matched == 0) Dbg(DateTime.Now.ToString("HH:mm:ss") + " idle visible=" + visible);
        }
    }

    class PillButton : Control
    {
        public Color Fill = Color.FromArgb(46, 213, 115);
        public bool Soft = false;
        bool hover;
        public PillButton()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Cursor = Cursors.Hand;
        }
        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Color c = hover ? ControlPaint.Light(Fill, 0.16f) : Fill;
            Rectangle r = new Rectangle(0, 0, Width - 1, Height - 1);
            int d = Math.Max(8, Math.Min(r.Height, Soft ? r.Height / 2 + 4 : r.Height));
            using (GraphicsPath gp = new GraphicsPath())
            {
                gp.AddArc(r.X, r.Y, d, d, 180, 90);
                gp.AddArc(r.Right - d, r.Y, d, d, 270, 90);
                gp.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
                gp.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
                gp.CloseFigure();
                using (SolidBrush b = new SolidBrush(c)) g.FillPath(b, gp);
            }
            TextRenderer.DrawText(g, Text, Font, r, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }

    // 设定自律时段
    class PlanForm : Form
    {
        public long PlanStart, PlanEnd;
        NumericUpDown nDur, nDelay;
        RadioButton rNow, rDelay;

        public PlanForm()
        {
            Text = "设定自律时段";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false; MinimizeBox = false;
            ShowInTaskbar = false;
            ClientSize = new Size(300, 236);
            BackColor = Color.FromArgb(28, 28, 34);
            ForeColor = Color.FromArgb(230, 230, 236);
            Font = new Font("Microsoft YaHei UI", 9f);

            Label l1 = new Label();
            l1.Text = "持续时长（分钟）";
            l1.AutoSize = true;
            l1.Location = new Point(18, 14);
            l1.ForeColor = Color.FromArgb(190, 190, 200);
            Controls.Add(l1);

            nDur = new NumericUpDown();
            nDur.Minimum = 1; nDur.Maximum = 1440; nDur.Value = 45;
            nDur.Location = new Point(18, 38);
            nDur.Size = new Size(78, 24);
            nDur.BackColor = Color.FromArgb(45, 45, 52);
            nDur.ForeColor = Color.White;
            nDur.BorderStyle = BorderStyle.FixedSingle;
            Controls.Add(nDur);

            int px = 106;
            foreach (int v in new int[] { 15, 25, 45, 60, 90 })
            {
                Button b = new Button();
                b.Text = v.ToString();
                b.Location = new Point(px, 38);
                b.Size = new Size(34, 24);
                b.FlatStyle = FlatStyle.Flat;
                b.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 92);
                b.BackColor = Color.FromArgb(45, 45, 52);
                b.ForeColor = Color.FromArgb(220, 220, 228);
                int vv = v;
                b.Click += delegate { nDur.Value = vv; };
                Controls.Add(b);
                px += 36;
            }

            GroupBox gb = new GroupBox();
            gb.Text = "开始时间";
            gb.ForeColor = Color.FromArgb(190, 190, 200);
            gb.Location = new Point(18, 78);
            gb.Size = new Size(264, 96);
            Controls.Add(gb);

            rNow = new RadioButton();
            rNow.Text = "立刻开始";
            rNow.Checked = true;
            rNow.AutoSize = true;
            rNow.Location = new Point(14, 26);
            rNow.ForeColor = Color.FromArgb(230, 230, 236);
            gb.Controls.Add(rNow);

            rDelay = new RadioButton();
            rDelay.Text = "推迟";
            rDelay.AutoSize = true;
            rDelay.Location = new Point(14, 56);
            rDelay.ForeColor = Color.FromArgb(230, 230, 236);
            gb.Controls.Add(rDelay);

            nDelay = new NumericUpDown();
            nDelay.Minimum = 1; nDelay.Maximum = 1440; nDelay.Value = 10;
            nDelay.Location = new Point(70, 54);
            nDelay.Size = new Size(66, 24);
            nDelay.BackColor = Color.FromArgb(45, 45, 52);
            nDelay.ForeColor = Color.White;
            nDelay.BorderStyle = BorderStyle.FixedSingle;
            gb.Controls.Add(nDelay);

            Label l5 = new Label();
            l5.Text = "分钟后开始";
            l5.AutoSize = true;
            l5.Location = new Point(142, 58);
            l5.ForeColor = Color.FromArgb(190, 190, 200);
            gb.Controls.Add(l5);

            Button ok = new Button();
            ok.Text = "开始自律";
            ok.Location = new Point(18, 190);
            ok.Size = new Size(120, 32);
            ok.FlatStyle = FlatStyle.Flat;
            ok.FlatAppearance.BorderColor = Color.FromArgb(46, 213, 115);
            ok.BackColor = Color.FromArgb(35, 90, 60);
            ok.ForeColor = Color.White;
            ok.Click += new EventHandler(OnOk);
            Controls.Add(ok);

            Button cancel = new Button();
            cancel.Text = "取消";
            cancel.Location = new Point(162, 190);
            cancel.Size = new Size(120, 32);
            cancel.FlatStyle = FlatStyle.Flat;
            cancel.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 92);
            cancel.BackColor = Color.FromArgb(45, 45, 52);
            cancel.ForeColor = Color.FromArgb(220, 220, 228);
            cancel.Click += delegate { DialogResult = DialogResult.Cancel; Close(); };
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;
        }

        void OnOk(object sender, EventArgs e)
        {
            long now = DateTime.Now.Ticks;
            long start = rNow.Checked ? now : now + (long)nDelay.Value * TimeSpan.TicksPerMinute;
            PlanStart = start;
            PlanEnd = start + (long)nDur.Value * TimeSpan.TicksPerMinute;
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    class LockForm : Form
    {
        const float BaseW = 262f, BaseH = 214f;
        const string SettingsPath = @"%APPDATA%\BiliLock\settings.txt";

        Label lblTitle, lblSub, lblStatus, lblSession, lblHint;
        PillButton pill, btnPlan, btnHide;
        System.Windows.Forms.Timer timer;
        Guard guard = new Guard();
        bool busy;
        int ticks;
        bool cachedOn;
        bool lastActive;
        string lastText = "";

        public LockForm()
        {
            Text = "B站自律锁";
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            TopMost = true;
            BackColor = Color.FromArgb(22, 22, 26);
            ShowInTaskbar = true;
            DoubleBuffered = true;
            AutoScaleMode = AutoScaleMode.None;

            lblTitle = MakeLabel("B站自律锁", 10f, FontStyle.Bold, Color.FromArgb(240, 240, 245), 16, 12, true);
            lblSub = MakeLabel("", 8f, FontStyle.Regular, Color.FromArgb(115, 115, 125), 118, 15, true);
            lblStatus = MakeLabel("", 8f, FontStyle.Regular, Color.FromArgb(140, 140, 152), 16, 92, false);
            lblSession = MakeLabel("", 8f, FontStyle.Regular, Color.FromArgb(150, 190, 160), 16, 146, false);
            lblHint = MakeLabel("右键：菜单", 7.5f, FontStyle.Regular, Color.FromArgb(120, 120, 132), 16, 180, true);

            btnHide = new PillButton();
            btnHide.Soft = true;
            btnHide.Fill = Color.FromArgb(64, 64, 76);
            btnHide.Font = new Font("Microsoft YaHei UI", 8f, FontStyle.Regular);
            btnHide.Text = "隐藏";
            btnHide.Size = new Size(46, 22);
            btnHide.Location = new Point(200, 10);
            btnHide.Click += new EventHandler(delegate { HidePanel(); });
            Controls.Add(btnHide);
            pill = new PillButton();
            pill.Font = new Font("Microsoft YaHei UI", 11f, FontStyle.Bold);
            pill.Click += new EventHandler(Pill_Click);
            Controls.Add(pill);

            btnPlan = new PillButton();
            btnPlan.Soft = true;
            btnPlan.Fill = Color.FromArgb(58, 58, 70);
            btnPlan.Font = new Font("Microsoft YaHei UI", 9f, FontStyle.Regular);
            btnPlan.Click += new EventHandler(Plan_Click);
            Controls.Add(btnPlan);

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("设定自律时段…", null, delegate { Plan_Click(null, null); });
            menu.Items.Add("还原 hosts 并退出", null, delegate { RestoreAndExit(); });
            menu.Items.Add("退出（保持当前封锁）", null, delegate { TryClose(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("切换拦截动作（关窗口 / 最小化）", null, delegate { guard.MinimizeMode = !guard.MinimizeMode; UpdateStatus(); });
            ContextMenuStrip = menu;

            Load += new EventHandler(OnLoad);
            FormClosing += new FormClosingEventHandler(OnClosing);

            MouseDown += new MouseEventHandler(StartDrag);
            lblTitle.MouseDown += new MouseEventHandler(StartDrag);
            lblStatus.MouseDown += new MouseEventHandler(StartDrag);

            Session.LoadFromDisk();
            timer = new System.Windows.Forms.Timer();
            timer.Interval = 300;
            timer.Tick += new EventHandler(OnTick);
            cachedOn = HostsFile.IsEnabled();
            timer.Start();
            WatchShowEvent();
        }

        // 静音开关：--notips 时不弹任何对话框（自动化测试用）
        public static bool TipsOff = false;

        // 同一个提示 10 秒内只弹一次，避免连点/多路径触发时弹一串
        static string _lastMsg = "";
        static DateTime _lastMsgAt = DateTime.MinValue;

        DialogResult ShowMsg(string text, string title, MessageBoxButtons buttons, MessageBoxIcon icon)
        {
            Guard.Dbg("MSG[" + title + "] " + text.Replace("\r\n", " / "));
            if (TipsOff) return DialogResult.OK;

            bool plain = (buttons == MessageBoxButtons.OK);
            if (plain && text == _lastMsg && (DateTime.Now - _lastMsgAt).TotalSeconds < 10)
            {
                Guard.Dbg("MSG suppressed (dup)");
                return DialogResult.OK;
            }
            if (plain) { _lastMsg = text; _lastMsgAt = DateTime.Now; }
            return MessageBox.Show(this, text, title, buttons, icon);
        }
        Label MakeLabel(string text, float size, FontStyle style, Color color, int x, int y, bool autosize)
        {
            Label l = new Label();
            l.Text = text;
            l.ForeColor = color;
            l.Font = new Font("Microsoft YaHei UI", size, style);
            l.AutoSize = autosize;
            l.Location = new Point(x, y);
            if (!autosize) l.Size = new Size(230, 18);
            l.BackColor = Color.Transparent;
            Controls.Add(l);
            return l;
        }

        public void HidePanel()
        {
            Hide();
            Guard.Dbg("panel hidden");
        }

        public void ShowPanel()
        {
            try
            {
                if (!Visible) Show();
                WindowState = FormWindowState.Normal;
                TopMost = false; TopMost = true;
                BringToFront();
                Activate();
                UpdateStatus();
                Guard.Dbg("panel shown");
            }
            catch { }
        }

        void WatchShowEvent()
        {
            Thread th = new Thread(delegate()
            {
                while (true)
                {
                    try
                    {
                        if (SingleInstance.ShowEvent == null) { Thread.Sleep(500); continue; }
                        SingleInstance.ShowEvent.WaitOne();
                        if (IsDisposed) break;
                        try { BeginInvoke(new Action(ShowPanel)); }
                        catch { }
                    }
                    catch { Thread.Sleep(500); }
                }
            });
            th.IsBackground = true;
            th.Start();
        }
        void ApplyScale()
        {
            Size = new Size((int)BaseW, (int)BaseH);
            pill.Location = new Point(16, 42);
            pill.Size = new Size(230, 44);
            btnPlan.Location = new Point(16, 114);
            btnPlan.Size = new Size(230, 26);
        }

        void OnLoad(object sender, EventArgs e)
        {
            ApplyScale();
            Rectangle wa = Screen.PrimaryScreen.WorkingArea;
            int x = wa.Right - Width - 18;
            int y = wa.Bottom - Height - 18;
            try
            {
                string sp = Environment.ExpandEnvironmentVariables(SettingsPath);
                if (File.Exists(sp))
                {
                    string[] p = File.ReadAllLines(sp);
                    int px, py;
                    if (p.Length >= 2 && int.TryParse(p[0], out px) && int.TryParse(p[1], out py))
                    {
                        if (px >= wa.Left && px <= wa.Right - 60 && py >= wa.Top && py <= wa.Bottom - 60) { x = px; y = py; }
                    }
                }
            }
            catch { }
            Location = new Point(x, y);
            UpdateStatus();
            if (Program.AutoHideMs > 0)
            {
                System.Windows.Forms.Timer t2 = new System.Windows.Forms.Timer();
                t2.Interval = Program.AutoHideMs;
                t2.Tick += delegate { t2.Stop(); HidePanel(); };
                t2.Start();
            }

            // 自律进行中但封锁没生效（例如被外部改回去、或重启后）：自动提权重放
            if (Session.IsActive && !HostsFile.IsEnabled() && !IsAdmin())
            {
                try
                {
                    string a = "--session-start=" + Session.StartTicks + " --session-end=" + Session.EndTicks + " --takeover --quiet";
                    if (HostsFile.Path_ != HostsFile.DefaultPath) a = "--hostsfile=" + HostsFile.Path_ + " " + a;
                    ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, a);
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    Process.Start(psi);
                    Application.Exit();
                    return;
                }
                catch { }
            }
        }

        void SaveSettings()
        {
            try
            {
                string sp = Environment.ExpandEnvironmentVariables(SettingsPath);
                string dir = Path.GetDirectoryName(sp);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(sp, Location.X + Environment.NewLine + Location.Y);
            }
            catch { }
        }

        int dragX, dragY;
        bool dragging;
        void StartDrag(object sender, MouseEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            dragX = e.X; dragY = e.Y; dragging = true;
        }
        protected override void OnMouseMove(MouseEventArgs e)
        {
            if (dragging)
            {
                Point p = PointToScreen(new Point(e.X, e.Y));
                Location = new Point(p.X - dragX, p.Y - dragY);
            }
            base.OnMouseMove(e);
        }
        protected override void OnMouseUp(MouseEventArgs e)
        {
            dragging = false;
            SaveSettings();
            base.OnMouseUp(e);
        }

        static bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        void OnTick(object sender, EventArgs e)
        {
            ticks++;
            if (ticks % 5 == 0) cachedOn = HostsFile.IsEnabled();
            bool active = Session.IsActive;

            if (active)
            {
                // 自律期间：hosts 被改回去就补回来（自愈）
                if (!HostsFile.IsEnabled())
                {
                    try { HostsFile.Apply(); HostsFile.FlushDns(); DohPolicy.Disable(); } catch { }
                    cachedOn = true;
                }
                int b1 = guard.Closed, b2 = guard.Failed;
                guard.Scan();
                if (guard.Closed != b1 || guard.Failed != b2) UpdateStatus();
                string rem = Session.RemainText();
                if (rem != lastText) { lastText = rem; UpdateStatus(); }
            }
            else
            {
                if (lastActive && DateTime.Now.Ticks >= Session.EndTicks)
                {
                    Session.Clear();
                    try { HostsFile.Restore(); DohPolicy.Restore(); HostsFile.FlushDns(); } catch { }
                    cachedOn = HostsFile.IsEnabled();
                    lastText = "";
                    UpdateStatus();
                    ShowMsg("自律时段结束，封锁已自动解除，hosts 已还原。", "时间到",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                if (cachedOn)
                {
                    int b1 = guard.Closed, b2 = guard.Failed;
                    guard.Scan();
                    if (guard.Closed != b1 || guard.Failed != b2) UpdateStatus();
                }
                if (Session.IsPending)
                {
                    string rem = Session.UntilText();
                    if (rem != lastText) { lastText = rem; UpdateStatus(); }
                }
            }
            lastActive = active;
        }

        void UpdateStatus()
        {
            bool active = Session.IsActive;
            bool pending = Session.IsPending;

            if (active)
            {
                pill.Text = "自律中 · " + Session.RemainText();
                pill.Fill = Color.FromArgb(30, 150, 90);
                pill.Cursor = Cursors.No;
                btnPlan.Text = "自律期间不可解除";
                btnPlan.Enabled = false;
                lblStatus.Text = string.Format("hosts {0} 条 · 已拦 {1}", HostsFile.EnabledCount(), guard.Closed);
                lblSession.Text = "至 " + Session.ClockText(Session.EndTicks) + " 结束";
                pill.Invalidate();
                return;
            }

            btnPlan.Enabled = true;
            pill.Cursor = Cursors.Hand;

            if (HostsFile.IsEnabled())
            {
                pill.Text = "已封锁 · 点我解除";
                pill.Fill = Color.FromArgb(46, 213, 115);
                lblStatus.Text = string.Format("hosts {0} 条 · 已拦 {1}{2}", HostsFile.EnabledCount(), guard.Closed,
                    guard.Failed > 0 ? (" · 失败 " + guard.Failed) : "");
            }
            else
            {
                pill.Text = "已放行 · 点我封锁";
                pill.Fill = Color.FromArgb(96, 96, 106);
                lblStatus.Text = "未启用封锁";
            }

            if (pending)
            {
                btnPlan.Text = "已排程 · 点我取消（" + Session.UntilText() + " 后开始）";
                lblSession.Text = Session.ClockText(Session.StartTicks) + " 开始 · " +
                    Session.Fmt(TimeSpan.FromTicks(Session.EndTicks - Session.StartTicks)) + " 时长";
            }
            else
            {
                btnPlan.Text = "设定自律时段…";
                lblSession.Text = "";
            }
            pill.Invalidate();
            btnPlan.Invalidate();
        }

        void Pill_Click(object sender, EventArgs e)
        {
            if (Session.IsActive)
            {
                ShowMsg("自律进行中，还剩 " + Session.RemainText() + "。\r\n这段时间面板不提供解除入口。",
                    "自律中", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (busy) return;
            busy = true;
            try
            {
                if (HostsFile.IsEnabled())
                {
                    if (ElevatedRun("--restore"))
                    {
                        guard.Closed = 0;
                        cachedOn = false;
                        ShowMsg("已解除封锁，hosts 已还原。", "B站自律锁", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
                else
                {
                    if (ElevatedRun("--apply"))
                    {
                        cachedOn = true;
                        ShowMsg("已开启封锁。", "B站自律锁", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
                cachedOn = HostsFile.IsEnabled();
            }
            finally { busy = false; }
            UpdateStatus();
        }

        void Plan_Click(object sender, EventArgs e)
        {
            if (Session.IsActive)
            {
                ShowMsg("自律进行中，无法修改或取消。", "自律中", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (Session.IsPending)
            {
                if (ShowMsg("当前排程：" + Session.ClockText(Session.StartTicks) + " 开始，还剩 " +
                    Session.UntilText() + "。\r\n要取消这次排程吗？", "取消排程",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    Session.Clear();
                    UpdateStatus();
                }
                return;
            }

            using (PlanForm pf = new PlanForm())
            {
                if (pf.ShowDialog(this) != DialogResult.OK) return;
                DateTime st = new DateTime(pf.PlanStart);
                string tip = "自律时段：" + st.ToString("MM-dd HH:mm") + " 开始，持续 " +
                    Session.Fmt(TimeSpan.FromTicks(pf.PlanEnd - pf.PlanStart)) + "。\r\n\r\n" +
                    "开始之后到结束之前，程序内不能解除封锁，也不能关闭面板。\r\n确定？";
                if (MessageBox.Show(this, tip, "确认自律", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return;

                Session.Save(pf.PlanStart, pf.PlanEnd);
                if (!IsAdmin())
                {
                    // 交给提权实例运行，保证自律期间有权限自愈
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath,
                            "--session-start=" + Session.StartTicks + " --session-end=" + Session.EndTicks + " --takeover --quiet");
                        psi.UseShellExecute = true;
                        psi.Verb = "runas";
                        Process.Start(psi);
                        Application.Exit();
                        return;
                    }
                    catch
                    {
                        ShowMsg("开始自律需要管理员权限，请在 UAC 弹窗点“是”。", "B站自律锁",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
                try { HostsFile.Apply(); DohPolicy.Disable(); HostsFile.FlushDns(); } catch { }
                cachedOn = HostsFile.IsEnabled();
            }
            UpdateStatus();
        }

        bool ElevatedRun(string arg)
        {
            try
            {
                if (IsAdmin())
                {
                    if (arg == "--apply") { HostsFile.Apply(); DohPolicy.Disable(); }
                    else { HostsFile.Restore(); DohPolicy.Restore(); }
                    HostsFile.FlushDns();
                    return true;
                }
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, arg + " --quiet");
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process p = Process.Start(psi);
                if (p == null) return false;
                p.WaitForExit(60000);
                return true;
            }
            catch (Exception ex)
            {
                ShowMsg("改 hosts 需要提权，请在 UAC 弹窗点“是”。\r\n\r\n" + ex.Message, "B站自律锁", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
        }

        void RestoreAndExit()
        {
            if (Session.IsActive)
            {
                ShowMsg("自律进行中，不能还原。", "自律中", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (Session.IsPending)
            {
                ShowMsg("有排程中的自律时段，请先取消排程。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            ElevatedRun("--restore");
            Close();
        }

        void TryClose()
        {
            if (Session.IsActive)
            {
                ShowMsg("自律进行中，无法退出面板。\r\n封锁会一直生效到 " + Session.ClockText(Session.EndTicks) + "。",
                    "自律中", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Close();
        }

        void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (Session.IsActive && e.CloseReason != CloseReason.WindowsShutDown && e.CloseReason != CloseReason.TaskManagerClosing)
            {
                e.Cancel = true;
                ShowMsg("自律进行中，无法关闭。\r\n剩余 " + Session.RemainText() + "。",
                    "自律中", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
    }

    static class Program
    {
        public static int AutoHideMs = 0;
        public static bool NoPersist = false;

        [STAThread]
        static void Main(string[] args)
        {
            string mode = null;
            long sArg = 0, eArg = 0;
            foreach (string a in args)
            {
                if (a == "--quiet") continue;
                else if (a == "--apply") mode = "apply";
                else if (a == "--restore") mode = "restore";
                else if (a.StartsWith("--hostsfile=", StringComparison.OrdinalIgnoreCase))
                    HostsFile.Path_ = a.Substring("--hostsfile=".Length);
                else if (a.StartsWith("--session-start=", StringComparison.OrdinalIgnoreCase))
                    long.TryParse(a.Substring("--session-start=".Length), out sArg);
                else if (a.StartsWith("--session-end=", StringComparison.OrdinalIgnoreCase))
                    long.TryParse(a.Substring("--session-end=".Length), out eArg);
                else if (a == "--selftest") { RunSelfTest(); return; }
                else if (a == "--showplan") { mode = "showplan"; }
                else if (a == "--notips") { LockForm.TipsOff = true; }
                else if (a.StartsWith("--autohide=", StringComparison.OrdinalIgnoreCase)) int.TryParse(a.Substring(11), out AutoHideMs);
                else if (a == "--no-persist") NoPersist = true;
            }

            if (sArg > 0 && eArg > sArg)
            {
                Session.StartTicks = sArg; Session.EndTicks = eArg;
                if (NoPersist) { LaunchGui(); return; }
                try
                {
                    File.WriteAllText(Path.Combine(Session.Dir, "session.txt"),
                        sArg + Environment.NewLine + eArg + Environment.NewLine, new UTF8Encoding(false));
                }
                catch { }
            }

            if (mode == "showplan")
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new PlanForm());
                return;
            }

            if (mode != null)
            {
                try
                {
                    if (mode == "apply") { HostsFile.Apply(); DohPolicy.Disable(); }
                    else { HostsFile.Restore(); DohPolicy.Restore(); }
                    HostsFile.FlushDns();
                }
                catch { }
                return;
            }

            bool takeover = false;
            foreach (string a in args) if (a == "--takeover") takeover = true;

            if (!SingleInstance.Acquire(takeover))
            {
                SingleInstance.RaiseShow();   // 已有实例：把它叫出来，自己退出
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new LockForm());
        }

        static void LaunchGui()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new LockForm());
        }

        static void RunSelfTest()
        {
            StringBuilder o = new StringBuilder();
            string dir = Path.GetDirectoryName(Application.ExecutablePath);
            string log = Path.Combine(dir, "selftest.log");
            string tmp = Path.Combine(dir, "selftest-hosts.txt");
            File.WriteAllText(tmp, "# original" + Environment.NewLine + "127.0.0.1 localhost" + Environment.NewLine);
            HostsFile.Path_ = tmp;
            o.AppendLine("1. init enabled=" + HostsFile.IsEnabled());
            HostsFile.Apply();
            o.AppendLine("2. apply enabled=" + HostsFile.IsEnabled() + " count=" + HostsFile.EnabledCount());
            HostsFile.Apply();
            o.AppendLine("3. apply again count=" + HostsFile.EnabledCount());
            HostsFile.Restore();
            o.AppendLine("4. restore enabled=" + HostsFile.IsEnabled() + " content=[" + File.ReadAllText(tmp).Trim().Replace(Environment.NewLine, " | ") + "]");

            long now = DateTime.Now.Ticks;
            Session.StartTicks = now - TimeSpan.TicksPerMinute;
            Session.EndTicks = now + TimeSpan.TicksPerMinute * 44;
            o.AppendLine("5. running: active=" + Session.IsActive + " pending=" + Session.IsPending + " remain=" + Session.RemainText());
            Session.StartTicks = now + TimeSpan.TicksPerMinute * 10;
            Session.EndTicks = now + TimeSpan.TicksPerMinute * 55;
            o.AppendLine("6. future: active=" + Session.IsActive + " pending=" + Session.IsPending + " until=" + Session.UntilText());
            Session.StartTicks = now - TimeSpan.TicksPerMinute * 90;
            Session.EndTicks = now - TimeSpan.TicksPerMinute * 30;
            o.AppendLine("7. expired: active=" + Session.IsActive + " pending=" + Session.IsPending);
            o.AppendLine("8. fmt " + Session.Fmt(TimeSpan.FromMinutes(45)) + " / " + Session.Fmt(TimeSpan.FromMinutes(125)) + " / " + Session.Fmt(TimeSpan.FromMinutes(1500)));

            Regex re = new Regex(Rules.TitlePattern);
            string[] samples = new string[] { "【4K】x_哔哩哔哩_bilibili", "哔哩哔哩 干杯", "b23.tv 短链", "Microsoft Edge" };
            foreach (string s2 in samples) o.AppendLine("   " + (re.IsMatch(s2) ? "[HIT]" : "[PASS]") + " " + s2);

            File.Delete(tmp);
            o.AppendLine("DONE");
            File.WriteAllText(log, o.ToString(), new UTF8Encoding(false));
        }
    }
}
