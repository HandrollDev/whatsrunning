"""Known process database for WhatsRunning.

Each entry maps an executable name (lowercase) to metadata describing what it is,
who publishes it, where it usually lives, and how trustworthy it is by default.

Trust levels:
    trusted  - Core Windows / major vendor system process. Strong prior of safety.
    common   - Recognised third-party software. Safe in expected location.
    neutral  - Recognised but not security-relevant either way.
"""

WINDOWS = r"C:\Windows"
SYS32 = r"C:\Windows\System32"
SYSWOW = r"C:\Windows\SysWOW64"
PROGFILES = r"C:\Program Files"
PROGFILES86 = r"C:\Program Files (x86)"


PROCESS_DB = {
    # ---------- Windows Core / Kernel ----------
    "system": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "The Windows kernel itself, surfaced as a process so the OS can account for kernel-mode CPU time. You can't close it — the system can't run without it. Exactly one instance, always.",
        "expected_paths": [],
        "trust": "trusted",
    },
    "system idle process": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "A fake placeholder process that represents idle CPU time. High CPU here is the *good* kind — it means your computer is doing nothing. Can't be closed and doesn't actually consume anything.",
        "expected_paths": [],
        "trust": "trusted",
    },
    "registry": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Holds the Windows Registry hive in memory — the database of system and app settings. Has no .exe on disk; Windows manufactures the process. Can't be closed; everything depends on it.",
        "expected_paths": [],
        "trust": "trusted",
    },
    "memory compression": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Squeezes rarely-used RAM into compressed form so Windows can fit more in memory without writing to disk. Saves you from slow paging when RAM is tight. High memory here is fine — it's *holding* compressed pages, not leaking. Can't be closed.",
        "expected_paths": [],
        "trust": "trusted",
    },
    "smss.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Session Manager — the first program Windows runs after the kernel. It creates user sessions, launches login, and then quietly waits. Can't be closed; killing it would crash Windows.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "csrss.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Client/Server Runtime — handles console windows (cmd, PowerShell) and helps Windows create and destroy processes. Normal to see two: one for your session, one for the system. Killing it triggers a Blue Screen by design (it's that critical).",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "wininit.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Windows Initialization — runs at boot to launch services.exe, lsass.exe, and lsm.exe, then stays running. Don't close it; it manages the entire system-services session.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "winlogon.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Handles signing in, signing out, locking the screen, and the Ctrl+Alt+Del 'secure attention' sequence. Always running while you're logged in. Don't close it — your session ends if it dies.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "services.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Service Control Manager — starts, stops, and supervises every Windows service. If your printer service or networking service crashes, this restarts it. Can't be closed; killing it forces a reboot.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "lsass.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Local Security Authority — verifies your password at login and holds your active credentials. Malware sometimes impersonates this name: real lsass *only* lives in C:\\Windows\\System32. Don't close it; you'll be signed out instantly.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "lsaiso.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "LSA Isolated — runs Credential Guard in a hardware-isolated container so even kernel malware can't read your passwords. Only present if Credential Guard is enabled (common on enterprise PCs). Leave it alone.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "svchost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Service Host — runs Windows services packaged as DLLs. Windows splits its services across many svchost instances so a crash in one (say, printing) doesn't take down the others (networking, audio). It's normal to see 30+. Don't close them — features will break and Windows usually restarts them within seconds anyway.",
        "expected_paths": [SYS32, SYSWOW],
        "trust": "trusted",
    },
    "dwm.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Desktop Window Manager — composites every window into the final image you see. Without it, transparency, animations, and proper multi-monitor wouldn't work. Always running. Killing it briefly blanks the screen before Windows restarts it.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "explorer.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "The Windows shell — your taskbar, Start menu, system tray, and File Explorer windows are all this process. If the taskbar freezes, end this process; Windows restarts it within a second and your apps keep running.",
        "expected_paths": [WINDOWS],
        "trust": "trusted",
    },
    "taskhostw.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Task Host — runs scheduled tasks that are packaged as DLLs instead of standalone programs (Windows Update checks, telemetry uploads, cleanup tasks). Multiple instances are normal. Safe to close any one; Windows will start a new one when the next task fires.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "sihost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Shell Infrastructure Host — runs visual shell features like Action Center, transparency effects, and taskbar tooltips. Killing it can make the Start menu and notifications flake out until you restart.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "ctfmon.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Manages alternative text input: handwriting recognition, IMEs (for Japanese/Chinese/Korean), and speech-to-text. Runs even if you don't use these. Safe to close, but Windows usually restarts it.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "fontdrvhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "User-mode Font Driver Host — renders fonts in a sandboxed process so a malformed font file can't crash the whole system. Two instances are normal (one per session). Leave it alone.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "conhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Provides the actual window for cmd.exe and powershell.exe consoles. One conhost per open terminal. Closing it closes that terminal window.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "runtimebroker.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Acts as the gatekeeper between Microsoft Store apps and your sensitive resources (location, microphone, files). When a Store app asks for permission, this is what shows the prompt. One per running Store app, so several instances are normal.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "searchhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "The search box on your taskbar. Renders the dropdown of files, apps, and web suggestions. Safe to close; Windows restarts it the next time you hit Start or click the search box.",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "searchindexer.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Quietly reads files, email, and Start menu shortcuts to build the index that makes Windows Search instant. Idle most of the time; uses CPU and disk after you install lots of files. Killing it makes search slow until the index rebuilds.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "searchprotocolhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Sandboxed helper that opens random files (PDFs, .docx, source code) on behalf of the search indexer. Sandboxing means a malformed file can't crash the indexer. Comes and goes during indexing.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "searchfilterhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Sandbox that runs the actual content-extraction code for each file type during indexing. Spawned by searchindexer, terminates when done.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "startmenuexperiencehost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Renders the Start menu itself. Always running so the menu opens instantly. Safe to close (the menu briefly disappears and comes back).",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "shellexperiencehost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Renders the taskbar's flyouts (calendar, volume, notifications). Always running while you're logged in. Safe to close; you'll briefly lose those flyouts.",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "applicationframehost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Provides the title-bar window frame around Microsoft Store apps (Calculator, Photos, Settings, etc). One instance handles every Store app you have open. Killing it closes those windows.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "audiodg.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Audio Device Graph Isolation — the sandboxed engine that mixes sound from every app and sends it to your speakers/headphones. Running because something is using audio (even Windows sounds). If it's eating CPU, an app or audio effect is doing heavy DSP. Killing it kills all sound until it restarts.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "spoolsv.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Print Spooler — queues print jobs and sends them to your printer. Runs even with no printer attached (Windows assumes you might add one). Safe to disable in services.msc if you never print.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "wudfhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Runs hardware drivers (mostly USB devices, fingerprint readers, biometric sensors) in user mode instead of kernel mode, so a buggy driver can't blue-screen the whole system. Lots of devices = lots of these.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "dashost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Device Association Framework — helps Windows pair with Bluetooth and other wireless devices. Comes alive when you 'Add a device'; otherwise mostly idle.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "dllhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "COM Surrogate — a generic host that runs DLL-based components in a separate process so a crash in (say) a video-thumbnail codec doesn't take Explorer down with it. Multiple instances are normal.",
        "expected_paths": [SYS32, SYSWOW],
        "trust": "trusted",
    },
    "rundll32.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Generic Windows helper that runs a function inside a DLL. Used legitimately by control panels, drivers, and uninstallers — but also a favourite of malware. If you don't recognise the DLL in the command line, that's worth investigating.",
        "expected_paths": [SYS32, SYSWOW],
        "trust": "trusted",
    },
    "wmiprvse.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "WMI Provider Host — answers system-information queries from Task Manager, monitoring scripts, antivirus, and remote management tools. Spawns multiple instances as different tools query in parallel.",
        "expected_paths": [r"C:\Windows\System32\wbem"],
        "trust": "trusted",
    },
    "wmiapsrv.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "WMI Performance Adapter. Exposes performance counters to WMI.",
        "expected_paths": [r"C:\Windows\System32\wbem"],
        "trust": "trusted",
    },
    "msdtc.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Distributed Transaction Coordinator. Coordinates transactions across resources (mostly databases).",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "lsm.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Local Session Manager. Manages terminal-server connections to the local machine.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "userinit.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Runs logon scripts and starts the shell, then exits. Should not be running for long.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "taskmgr.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Task Manager — the built-in process viewer.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "winload.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Windows Boot Loader. Loads the kernel during boot.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "sppsvc.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Software Protection Platform. Handles Windows / Office licensing and activation.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "wlanext.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Wireless LAN extensibility host. Provides Wi-Fi vendor extensions.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "backgroundtaskhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Runs background tasks for Microsoft Store apps (notifications, sync, etc).",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "lockapp.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Renders the Windows lock screen.",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "logonui.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Displays the logon screen and accepts credentials.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "credentialuibroker.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Brokers UAC and credential prompts to UWP apps.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "useroobebroker.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Handles the out-of-box experience tasks for new user setups.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "csrss": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Alias for csrss.exe — see svchost description.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "winrshost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Windows Remote Shell host. Runs remote command-line sessions over WinRM.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },

    # ---------- Windows Security ----------
    "msmpeng.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Microsoft Defender's main antivirus engine — scans every file you open, every program you run, and every download. Running because Defender is on (the default). High CPU usually means a scheduled scan is in progress. Can't be closed without disabling Defender entirely in Group Policy.",
        "expected_paths": [r"C:\ProgramData\Microsoft\Windows Defender\Platform", r"C:\Program Files\Windows Defender"],
        "trust": "trusted",
    },
    "nissrv.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Defender's Network Inspection Service — watches network traffic for known malware signatures. Light footprint. Runs alongside the main Defender engine.",
        "expected_paths": [r"C:\ProgramData\Microsoft\Windows Defender\Platform", r"C:\Program Files\Windows Defender"],
        "trust": "trusted",
    },
    "securityhealthservice.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Backs the Windows Security app — the dashboard that shows whether your antivirus, firewall, and updates are healthy. Also drives the green/yellow/red shield icon. Idle most of the time.",
        "expected_paths": [SYS32, r"C:\Windows\System32\SecurityHealthService.exe"],
        "trust": "trusted",
    },
    "securityhealthsystray.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "The shield icon in your system tray — clicking it opens Windows Security. Just shows the status colour; doesn't do scanning itself. Safe to close (icon disappears until you sign in again).",
        "expected_paths": [SYS32, r"C:\Windows"],
        "trust": "trusted",
    },
    "smartscreen.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Checks downloaded files and visited URLs against Microsoft's reputation database. When you see 'Windows protected your PC' before running a new .exe, that's this. Sends a hash of the file/URL to Microsoft for the lookup (the only Microsoft phone-home that's hard to fully disable).",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "mpdefendercoreservice.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Microsoft Defender Core service. Hosts core Defender components.",
        "expected_paths": [r"C:\ProgramData\Microsoft\Windows Defender\Platform"],
        "trust": "trusted",
    },
    "mpcmdrun.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Defender command-line scanner. Usually invoked by scheduled tasks or admins.",
        "expected_paths": [r"C:\ProgramData\Microsoft\Windows Defender\Platform", r"C:\Program Files\Windows Defender"],
        "trust": "trusted",
    },

    # ---------- Browsers ----------
    "chrome.exe": {
        "category": "Browser",
        "publisher": "Google",
        "description": "Google Chrome. Every tab, extension, and the browser shell each run in their own chrome.exe — that's why there are so many. Memory adds up fast (a heavy single tab can use 500MB+). Safe to close any one — you'll lose that tab. Chrome's one-process-per-tab design is for security: a bad tab can't crash or read the others.",
        "expected_paths": [r"C:\Program Files\Google\Chrome", r"C:\Program Files (x86)\Google\Chrome", r"AppData\Local\Google\Chrome"],
        "trust": "common",
    },
    "msedge.exe": {
        "category": "Browser",
        "publisher": "Microsoft",
        "description": "Microsoft Edge — the Chromium-based browser built into Windows. Same one-process-per-tab design as Chrome. Often keeps running in the background after you close the window (for 'Startup Boost' and search-bar integration); turn those off in Edge's settings if you don't want it.",
        "expected_paths": [r"C:\Program Files (x86)\Microsoft\Edge", r"C:\Program Files\Microsoft\Edge"],
        "trust": "trusted",
    },
    "msedgewebview2.exe": {
        "category": "Browser",
        "publisher": "Microsoft",
        "description": "Embedded Chromium browser engine that other apps use to display web content — Outlook, new Teams, Office add-ins, Spotify, Discord, and many indie tools all rely on it. Multiple instances are normal (one or more per host app). Closing one will usually break or freeze whichever app spawned it.",
        "expected_paths": [r"C:\Program Files (x86)\Microsoft\EdgeWebView", r"C:\Program Files\Microsoft\EdgeWebView"],
        "trust": "trusted",
    },
    "firefox.exe": {
        "category": "Browser",
        "publisher": "Mozilla",
        "description": "Mozilla Firefox web browser. Uses a process-per-site model so tabs are isolated for security. Safe to close any one; that tab goes with it.",
        "expected_paths": [r"C:\Program Files\Mozilla Firefox", r"C:\Program Files (x86)\Mozilla Firefox"],
        "trust": "common",
    },
    "brave.exe": {
        "category": "Browser",
        "publisher": "Brave Software",
        "description": "Brave web browser — Chromium based, with built-in ad blocking.",
        "expected_paths": [r"C:\Program Files\BraveSoftware", r"C:\Program Files (x86)\BraveSoftware", r"AppData\Local\BraveSoftware"],
        "trust": "common",
    },
    "opera.exe": {
        "category": "Browser",
        "publisher": "Opera",
        "description": "Opera web browser.",
        "expected_paths": [r"AppData\Local\Programs\Opera", r"C:\Program Files\Opera"],
        "trust": "common",
    },
    "iexplore.exe": {
        "category": "Browser",
        "publisher": "Microsoft",
        "description": "Legacy Internet Explorer. Mostly retired on Windows 11.",
        "expected_paths": [r"C:\Program Files\Internet Explorer", r"C:\Program Files (x86)\Internet Explorer"],
        "trust": "trusted",
    },
    "vivaldi.exe": {
        "category": "Browser",
        "publisher": "Vivaldi Technologies",
        "description": "Vivaldi web browser — Chromium based, power-user focused.",
        "expected_paths": [r"AppData\Local\Vivaldi"],
        "trust": "common",
    },

    # ---------- Communication / Social ----------
    "discord.exe": {
        "category": "Communication",
        "publisher": "Discord Inc.",
        "description": "Discord chat / voice / video app. Built on Electron (a browser engine), so you'll see multiple discord.exe instances — one for the main UI, one or more for voice, plus helpers. Phones home for messages and presence info constantly while open. Safe to close — closing the window doesn't actually quit Discord by default (it minimizes to the tray); right-click the tray icon to fully exit.",
        "expected_paths": [r"AppData\Local\Discord"],
        "trust": "common",
    },
    "update.exe": {
        "category": "Communication",
        "publisher": "Squirrel (Various)",
        "description": "Squirrel updater used by Discord, Slack, GitHub Desktop, and other Electron apps. Check the parent folder.",
        "expected_paths": [r"AppData\Local"],
        "trust": "common",
    },
    "slack.exe": {
        "category": "Communication",
        "publisher": "Slack Technologies",
        "description": "Slack desktop app — workplace messaging. Electron-based so you'll see multiple slack.exe (main window, each workspace, helpers). Phones home constantly for new messages while running. Safe to close from the tray when you're done for the day.",
        "expected_paths": [r"AppData\Local\slack", r"C:\Program Files\Slack"],
        "trust": "common",
    },
    "teams.exe": {
        "category": "Communication",
        "publisher": "Microsoft",
        "description": "Microsoft Teams (classic / Electron version) — chat, voice, video, screen-sharing for work. Known to use a lot of RAM (multiple GB is normal). Auto-starts at login if your IT enabled it. Closing the window minimizes to tray; quit from the tray to actually stop it.",
        "expected_paths": [r"AppData\Local\Microsoft\Teams", r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "ms-teams.exe": {
        "category": "Communication",
        "publisher": "Microsoft",
        "description": "Microsoft Teams (new) — the rewritten version, runs on Edge WebView2 instead of Electron. Significantly lighter on RAM than classic Teams. Same auto-start / tray behaviour.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "zoom.exe": {
        "category": "Communication",
        "publisher": "Zoom Video Communications",
        "description": "Zoom video meetings. Often stays running in the background after a meeting ends so the next 'Join' is instant. Phones home for presence and meeting metadata while open. Safe to quit from the tray.",
        "expected_paths": [r"AppData\Roaming\Zoom", r"C:\Program Files\Zoom"],
        "trust": "common",
    },
    "skype.exe": {
        "category": "Communication",
        "publisher": "Microsoft",
        "description": "Skype messaging and calling.",
        "expected_paths": [r"C:\Program Files\WindowsApps", r"C:\Program Files (x86)\Microsoft\Skype for Desktop"],
        "trust": "trusted",
    },
    "telegram.exe": {
        "category": "Communication",
        "publisher": "Telegram FZ-LLC",
        "description": "Telegram desktop messenger.",
        "expected_paths": [r"AppData\Roaming\Telegram Desktop"],
        "trust": "common",
    },
    "whatsapp.exe": {
        "category": "Communication",
        "publisher": "WhatsApp",
        "description": "WhatsApp desktop client.",
        "expected_paths": [r"C:\Program Files\WindowsApps", r"AppData\Local"],
        "trust": "common",
    },
    "signal.exe": {
        "category": "Communication",
        "publisher": "Signal Foundation",
        "description": "Signal secure messenger.",
        "expected_paths": [r"AppData\Local\Programs\signal-desktop"],
        "trust": "common",
    },

    # ---------- Gaming ----------
    "steam.exe": {
        "category": "Gaming",
        "publisher": "Valve",
        "description": "Steam — game library, store, downloads, voice chat. The bootstrapper / coordinator process. While running it talks to Steam servers for friends, presence, and download manifests. Safe to close from the system tray when you're done playing; closing the X just hides it.",
        "expected_paths": [r"C:\Program Files (x86)\Steam", r"C:\Program Files\Steam"],
        "trust": "common",
    },
    "steamwebhelper.exe": {
        "category": "Gaming",
        "publisher": "Valve",
        "description": "Renders the Steam UI using embedded Chromium. Multiple instances are normal (one per Steam window — Library, Store, Friends, Big Picture, etc.). High memory in these is normal because each is essentially a browser tab.",
        "expected_paths": [r"C:\Program Files (x86)\Steam", r"C:\Program Files\Steam"],
        "trust": "common",
    },
    "steamservice.exe": {
        "category": "Gaming",
        "publisher": "Valve",
        "description": "The Steam background service — handles game installs and file integrity verification with admin privileges. Stays running even when the Steam client is closed, so installs/updates can continue without you being signed in.",
        "expected_paths": [r"C:\Program Files (x86)\Common Files\Steam"],
        "trust": "common",
    },
    "epicgameslauncher.exe": {
        "category": "Gaming",
        "publisher": "Epic Games",
        "description": "Epic Games Launcher — Fortnite, Unreal, free weekly games.",
        "expected_paths": [r"C:\Program Files (x86)\Epic Games", r"C:\Program Files\Epic Games"],
        "trust": "common",
    },
    "epicwebhelper.exe": {
        "category": "Gaming",
        "publisher": "Epic Games",
        "description": "Helper process for the Epic Games Launcher UI.",
        "expected_paths": [r"C:\Program Files (x86)\Epic Games", r"C:\Program Files\Epic Games"],
        "trust": "common",
    },
    "battle.net.exe": {
        "category": "Gaming",
        "publisher": "Blizzard Entertainment",
        "description": "Battle.net launcher for Blizzard games.",
        "expected_paths": [r"C:\Program Files (x86)\Battle.net"],
        "trust": "common",
    },
    "riotclientservices.exe": {
        "category": "Gaming",
        "publisher": "Riot Games",
        "description": "Riot Client services — backs League of Legends, Valorant, etc.",
        "expected_paths": [r"C:\Riot Games", r"C:\Program Files\Riot Games"],
        "trust": "common",
    },
    "vgc.exe": {
        "category": "Gaming",
        "publisher": "Riot Games",
        "description": "Vanguard anti-cheat service for Valorant. Runs at boot; can be uninstalled with Vanguard.",
        "expected_paths": [r"C:\Program Files\Riot Vanguard"],
        "trust": "common",
    },
    "ealauncher.exe": {
        "category": "Gaming",
        "publisher": "Electronic Arts",
        "description": "EA App launcher.",
        "expected_paths": [r"C:\Program Files\Electronic Arts"],
        "trust": "common",
    },
    "uplay.exe": {
        "category": "Gaming",
        "publisher": "Ubisoft",
        "description": "Ubisoft Connect (formerly Uplay) launcher.",
        "expected_paths": [r"C:\Program Files (x86)\Ubisoft"],
        "trust": "common",
    },
    "gog galaxy.exe": {
        "category": "Gaming",
        "publisher": "GOG / CD Projekt",
        "description": "GOG Galaxy game launcher.",
        "expected_paths": [r"C:\Program Files (x86)\GOG Galaxy"],
        "trust": "common",
    },
    "rockstargameslauncher.exe": {
        "category": "Gaming",
        "publisher": "Rockstar Games",
        "description": "Rockstar Games Launcher.",
        "expected_paths": [r"C:\Program Files\Rockstar Games"],
        "trust": "common",
    },
    "xboxapp.exe": {
        "category": "Gaming",
        "publisher": "Microsoft",
        "description": "Xbox app on Windows.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "gamebar.exe": {
        "category": "Gaming",
        "publisher": "Microsoft",
        "description": "Xbox Game Bar — overlay for screenshots, recording, performance.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },

    # ---------- Media ----------
    "spotify.exe": {
        "category": "Media",
        "publisher": "Spotify AB",
        "description": "Spotify music app. Several spotify.exe instances are normal (UI, audio engine, helpers). Closing the window minimizes to the tray; right-click the tray icon to fully quit. While running it streams audio and reports playback events back to Spotify (used for charts and your listening stats).",
        "expected_paths": [r"AppData\Roaming\Spotify", r"C:\Program Files\WindowsApps"],
        "trust": "common",
    },
    "vlc.exe": {
        "category": "Media",
        "publisher": "VideoLAN",
        "description": "VLC media player.",
        "expected_paths": [r"C:\Program Files\VideoLAN", r"C:\Program Files (x86)\VideoLAN"],
        "trust": "common",
    },
    "obs64.exe": {
        "category": "Media",
        "publisher": "OBS Project",
        "description": "OBS Studio — open-source streaming and recording.",
        "expected_paths": [r"C:\Program Files\obs-studio"],
        "trust": "common",
    },
    "obs32.exe": {
        "category": "Media",
        "publisher": "OBS Project",
        "description": "OBS Studio (32-bit) — open-source streaming and recording.",
        "expected_paths": [r"C:\Program Files (x86)\obs-studio"],
        "trust": "common",
    },
    "iTunes.exe": {
        "category": "Media",
        "publisher": "Apple",
        "description": "Apple iTunes media library.",
        "expected_paths": [r"C:\Program Files\iTunes", r"C:\Program Files (x86)\iTunes"],
        "trust": "common",
    },
    "applemusic.exe": {
        "category": "Media",
        "publisher": "Apple",
        "description": "Apple Music desktop app.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "common",
    },

    # ---------- Productivity / Office ----------
    "winword.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Microsoft Word.",
        "expected_paths": [r"C:\Program Files\Microsoft Office", r"C:\Program Files (x86)\Microsoft Office"],
        "trust": "trusted",
    },
    "excel.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Microsoft Excel.",
        "expected_paths": [r"C:\Program Files\Microsoft Office", r"C:\Program Files (x86)\Microsoft Office"],
        "trust": "trusted",
    },
    "powerpnt.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Microsoft PowerPoint.",
        "expected_paths": [r"C:\Program Files\Microsoft Office", r"C:\Program Files (x86)\Microsoft Office"],
        "trust": "trusted",
    },
    "outlook.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Microsoft Outlook email and calendar.",
        "expected_paths": [r"C:\Program Files\Microsoft Office", r"C:\Program Files (x86)\Microsoft Office"],
        "trust": "trusted",
    },
    "onenote.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Microsoft OneNote notes app.",
        "expected_paths": [r"C:\Program Files\Microsoft Office", r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "onedrive.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "OneDrive — syncs your Documents / Desktop / Pictures folders to Microsoft's cloud, and serves files on demand to other devices signed in to your Microsoft account. Auto-starts with Windows. Safe to quit from the tray; you can also unlink your account or uninstall it entirely if you don't use it.",
        "expected_paths": [r"AppData\Local\Microsoft\OneDrive", r"C:\Program Files\Microsoft OneDrive"],
        "trust": "trusted",
    },
    "googledrive.exe": {
        "category": "Productivity",
        "publisher": "Google",
        "description": "Google Drive sync client.",
        "expected_paths": [r"C:\Program Files\Google\Drive File Stream"],
        "trust": "common",
    },
    "dropbox.exe": {
        "category": "Productivity",
        "publisher": "Dropbox",
        "description": "Dropbox sync client.",
        "expected_paths": [r"AppData\Local\Dropbox", r"C:\Program Files (x86)\Dropbox"],
        "trust": "common",
    },
    "notion.exe": {
        "category": "Productivity",
        "publisher": "Notion Labs",
        "description": "Notion workspace and notes.",
        "expected_paths": [r"AppData\Local\Programs\Notion"],
        "trust": "common",
    },
    "obsidian.exe": {
        "category": "Productivity",
        "publisher": "Obsidian.md",
        "description": "Obsidian — local markdown knowledge base.",
        "expected_paths": [r"AppData\Local\Programs\Obsidian"],
        "trust": "common",
    },

    # ---------- Developer Tools ----------
    "code.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Visual Studio Code — Microsoft's code editor. Built on Electron, so you'll see many Code.exe instances (main, renderer, file watcher, extension host, language servers). Each open window adds more. Closing the main window quits them all. Language servers and extensions can be heavy — if you see high CPU, an extension is usually the cause.",
        "expected_paths": [r"AppData\Local\Programs\Microsoft VS Code", r"C:\Program Files\Microsoft VS Code"],
        "trust": "trusted",
    },
    "devenv.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Visual Studio IDE.",
        "expected_paths": [r"C:\Program Files\Microsoft Visual Studio", r"C:\Program Files (x86)\Microsoft Visual Studio"],
        "trust": "trusted",
    },
    "python.exe": {
        "category": "Developer",
        "publisher": "Python Software Foundation",
        "description": "Python interpreter — running because some app, script, or developer tool launched a Python program. The install path tells you which Python: 'WindowsApps\\PythonSoftwareFoundation' is the Microsoft Store version, 'AppData\\Local\\Programs\\Python' is the standard installer, anything under a project folder is a virtual environment. Safe to close any individual instance — that just kills that script. Won't auto-restart unless something is configured to retry.",
        "expected_paths": [
            r"AppData\Local\Python",
            r"AppData\Local\Programs\Python",
            r"C:\Python",
            r"C:\Users",
            r"WindowsApps\PythonSoftwareFoundation",
        ],
        "trust": "common",
    },
    "pythonw.exe": {
        "category": "Developer",
        "publisher": "Python Software Foundation",
        "description": "Same as python.exe but runs without showing a console window — used by Python GUI apps so they don't pop a black box behind their window. Safe to close any instance; closing the one running an app will close that app.",
        "expected_paths": [
            r"AppData\Local\Python",
            r"AppData\Local\Programs\Python",
            r"C:\Python",
            r"WindowsApps\PythonSoftwareFoundation",
        ],
        "trust": "common",
    },
    "node.exe": {
        "category": "Developer",
        "publisher": "OpenJS Foundation",
        "description": "Node.js — runs JavaScript outside a browser. Used by build tools (Webpack, Vite, npm), local dev servers, and many Electron-based apps. Multiple node.exe processes is normal: each running script is its own. Safe to close any one; that script stops.",
        "expected_paths": [r"C:\Program Files\nodejs", r"AppData\Roaming\nvm", r"AppData\Local"],
        "trust": "common",
    },
    "git.exe": {
        "category": "Developer",
        "publisher": "Git for Windows",
        "description": "The git version-control command-line tool. Always short-lived: it runs a command (commit, push, status) and exits. If you see git.exe sitting around long-term, it's probably stuck on a network operation (pull from a slow server, push waiting for credentials).",
        "expected_paths": [r"C:\Program Files\Git"],
        "trust": "common",
    },
    "bash.exe": {
        "category": "Developer",
        "publisher": "Git for Windows / WSL",
        "description": "Bash shell — usually from Git for Windows or WSL.",
        "expected_paths": [r"C:\Program Files\Git", SYS32],
        "trust": "common",
    },
    "wsl.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Windows Subsystem for Linux launcher.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "docker desktop.exe": {
        "category": "Developer",
        "publisher": "Docker Inc.",
        "description": "Docker Desktop — container runtime.",
        "expected_paths": [r"C:\Program Files\Docker"],
        "trust": "common",
    },
    "vctip.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Visual C++ telemetry helper. Bundled with the compiler.",
        "expected_paths": [r"C:\Program Files\Microsoft Visual Studio", r"C:\Program Files (x86)\Microsoft Visual Studio"],
        "trust": "trusted",
    },
    "javaw.exe": {
        "category": "Developer",
        "publisher": "Oracle / OpenJDK",
        "description": "Java runtime (windowless). Used by Minecraft Java, IDEs, and many apps.",
        "expected_paths": [r"C:\Program Files\Java", r"C:\Program Files (x86)\Java", r"C:\Program Files\Eclipse Adoptium"],
        "trust": "common",
    },
    "java.exe": {
        "category": "Developer",
        "publisher": "Oracle / OpenJDK",
        "description": "Java runtime.",
        "expected_paths": [r"C:\Program Files\Java", r"C:\Program Files (x86)\Java", r"C:\Program Files\Eclipse Adoptium"],
        "trust": "common",
    },

    # ---------- Shells / Terminals ----------
    "cmd.exe": {
        "category": "Shell",
        "publisher": "Microsoft",
        "description": "Windows Command Prompt. Usually short-lived (a single command runs, it exits). Long-running cmd.exe processes with no visible window — especially ones launched by Office or a browser — are worth investigating. Safe to close any cmd window you opened.",
        "expected_paths": [SYS32, SYSWOW],
        "trust": "trusted",
    },
    "powershell.exe": {
        "category": "Shell",
        "publisher": "Microsoft",
        "description": "Windows PowerShell 5.1 — the older built-in PowerShell. Used by many installers, scheduled tasks, and admin scripts. Also a top tool for malware: a powershell.exe with a long base64-encoded command line (-enc / -EncodedCommand) and no visible window is the classic 'living off the land' attack pattern. Legit when launched by a dev tool you trust.",
        "expected_paths": [r"C:\Windows\System32\WindowsPowerShell", r"C:\Windows\SysWOW64\WindowsPowerShell"],
        "trust": "trusted",
    },
    "pwsh.exe": {
        "category": "Shell",
        "publisher": "Microsoft",
        "description": "PowerShell 7+ — the modern cross-platform PowerShell. Same usage profile as powershell.exe: legit for dev tools and admin scripts, sometimes used as a malware loader. -EncodedCommand spawned by a parent you don't recognise is a red flag.",
        "expected_paths": [
            r"C:\Program Files\PowerShell",
            r"AppData\Local\Microsoft\PowerShell",
            r"WindowsApps\Microsoft.PowerShell",
        ],
        "trust": "trusted",
    },
    "windowsterminal.exe": {
        "category": "Shell",
        "publisher": "Microsoft",
        "description": "Windows Terminal — the modern tabbed window host for cmd, PowerShell, and WSL. Doesn't actually run commands itself; that's still cmd / PowerShell. Closing it closes all your terminal tabs.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "openconsole.exe": {
        "category": "Shell",
        "publisher": "Microsoft",
        "description": "Console host backing Windows Terminal.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },

    # ---------- GPU / Drivers ----------
    "nvcontainer.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "Generic NVIDIA service host — runs the various NVIDIA background services (display, broadcast, telemetry). Multiple instances are normal, one per feature. Auto-starts with Windows; closing one usually stops a related NVIDIA feature until restart.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation"],
        "trust": "common",
    },
    "nvdisplay.container.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "Backs the NVIDIA Control Panel (right-click desktop → NVIDIA Control Panel). Always running so the panel opens instantly. Safe to close, but the next time you open the control panel it'll relaunch.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation", r"C:\Windows\System32\DriverStore"],
        "trust": "common",
    },
    "nvtelemetrycontainer.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "NVIDIA's telemetry service — sends usage statistics back to NVIDIA. Optional and can be safely disabled in services.msc (search 'NVIDIA Telemetry') if you'd prefer not to share that data.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation"],
        "trust": "common",
    },
    "nvidia share.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "GeForce Experience overlay and ShadowPlay recording. Press Alt+Z to open the overlay. Holds a small video buffer in memory so you can save 'the last 30 seconds'. Safe to close if you don't use the overlay/recording.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation"],
        "trust": "common",
    },
    "nvidia web helper.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "Background helper used by GeForce Experience — checks for driver updates and game ready profiles. Phones home to NVIDIA. Disable GeForce Experience auto-start to remove it.",
        "expected_paths": [r"C:\Program Files (x86)\NVIDIA Corporation", r"C:\Program Files\NVIDIA Corporation"],
        "trust": "common",
    },
    "nvbroadcast.container.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "NVIDIA Broadcast — AI noise suppression, background blur/replacement for your webcam, and similar effects for streaming. Only runs if you have NVIDIA Broadcast installed; safe to close if you're not streaming.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation"],
        "trust": "common",
    },
    "amdrsserv.exe": {
        "category": "Drivers",
        "publisher": "AMD",
        "description": "AMD Radeon Software service.",
        "expected_paths": [r"C:\Program Files\AMD"],
        "trust": "common",
    },
    "radeonsoftware.exe": {
        "category": "Drivers",
        "publisher": "AMD",
        "description": "AMD Radeon Software UI.",
        "expected_paths": [r"C:\Program Files\AMD"],
        "trust": "common",
    },
    "igfxext.exe": {
        "category": "Drivers",
        "publisher": "Intel",
        "description": "Intel graphics extension module.",
        "expected_paths": [SYS32],
        "trust": "common",
    },
    "igfxem.exe": {
        "category": "Drivers",
        "publisher": "Intel",
        "description": "Intel graphics command/event manager.",
        "expected_paths": [SYS32],
        "trust": "common",
    },
    "rtkauduservice64.exe": {
        "category": "Drivers",
        "publisher": "Realtek",
        "description": "Realtek HD Audio service.",
        "expected_paths": [r"C:\Program Files\Realtek", r"C:\Windows\System32\DriverStore"],
        "trust": "common",
    },
    "armouryswagent.exe": {
        "category": "Drivers",
        "publisher": "ASUS",
        "description": "ASUS Armoury Crate agent. Hardware control and RGB for ASUS gear.",
        "expected_paths": [r"C:\Program Files\ASUS"],
        "trust": "common",
    },
    "logioptionsplus_agent.exe": {
        "category": "Drivers",
        "publisher": "Logitech",
        "description": "Logitech Options+ agent. Configures Logitech mice/keyboards.",
        "expected_paths": [r"C:\Program Files\Logi"],
        "trust": "common",
    },
    "lghub.exe": {
        "category": "Drivers",
        "publisher": "Logitech",
        "description": "Logitech G HUB — gaming peripheral suite.",
        "expected_paths": [r"C:\Program Files\LGHUB"],
        "trust": "common",
    },
    "razercentralservice.exe": {
        "category": "Drivers",
        "publisher": "Razer",
        "description": "Razer Synapse / Central service.",
        "expected_paths": [r"C:\Program Files (x86)\Razer", r"C:\ProgramData\Razer"],
        "trust": "common",
    },
    "corsair.service.exe": {
        "category": "Drivers",
        "publisher": "Corsair",
        "description": "Corsair iCUE service.",
        "expected_paths": [r"C:\Program Files\Corsair"],
        "trust": "common",
    },
    "icue.exe": {
        "category": "Drivers",
        "publisher": "Corsair",
        "description": "Corsair iCUE UI.",
        "expected_paths": [r"C:\Program Files\Corsair"],
        "trust": "common",
    },

    # ---------- Utilities ----------
    "7zfm.exe": {
        "category": "Utility",
        "publisher": "Igor Pavlov",
        "description": "7-Zip File Manager.",
        "expected_paths": [r"C:\Program Files\7-Zip", r"C:\Program Files (x86)\7-Zip"],
        "trust": "common",
    },
    "winrar.exe": {
        "category": "Utility",
        "publisher": "RARLAB",
        "description": "WinRAR archive utility.",
        "expected_paths": [r"C:\Program Files\WinRAR", r"C:\Program Files (x86)\WinRAR"],
        "trust": "common",
    },
    "powertoys.exe": {
        "category": "Utility",
        "publisher": "Microsoft",
        "description": "Microsoft PowerToys — productivity utilities (FancyZones, PowerRename, etc).",
        "expected_paths": [r"C:\Program Files\PowerToys"],
        "trust": "trusted",
    },
    "everything.exe": {
        "category": "Utility",
        "publisher": "voidtools",
        "description": "Everything — instant file search by name.",
        "expected_paths": [r"C:\Program Files\Everything", r"C:\Program Files (x86)\Everything"],
        "trust": "common",
    },
    "screentogif.exe": {
        "category": "Utility",
        "publisher": "Nicke Manarin",
        "description": "ScreenToGif — screen recorder.",
        "expected_paths": [r"AppData\Local"],
        "trust": "common",
    },
    "sharex.exe": {
        "category": "Utility",
        "publisher": "ShareX Team",
        "description": "ShareX — screenshots and screen recording.",
        "expected_paths": [r"C:\Program Files\ShareX"],
        "trust": "common",
    },
    "autohotkey.exe": {
        "category": "Utility",
        "publisher": "AutoHotkey Foundation",
        "description": "AutoHotkey — scripting tool for keyboard shortcuts, automation, and macros.",
        "expected_paths": [r"C:\Program Files\AutoHotkey"],
        "trust": "common",
    },
    "autohotkey64.exe": {
        "category": "Utility",
        "publisher": "AutoHotkey Foundation",
        "description": "AutoHotkey 64-bit — scripting tool for keyboard shortcuts and automation.",
        "expected_paths": [r"C:\Program Files\AutoHotkey"],
        "trust": "common",
    },
    "greenshot.exe": {
        "category": "Utility",
        "publisher": "Greenshot",
        "description": "Greenshot — open-source screenshot tool.",
        "expected_paths": [r"C:\Program Files\Greenshot"],
        "trust": "common",
    },
    "flux.exe": {
        "category": "Utility",
        "publisher": "Michael Herf",
        "description": "f.lux — adjusts screen colour temperature based on time of day.",
        "expected_paths": [r"AppData\Local\FluxSoftware"],
        "trust": "common",
    },
    "rainmeter.exe": {
        "category": "Utility",
        "publisher": "Rainmeter",
        "description": "Rainmeter — customizable desktop widgets and skins.",
        "expected_paths": [r"C:\Program Files\Rainmeter"],
        "trust": "common",
    },

    # ---------- AI / IDE tools ----------
    "codex.exe": {
        "category": "Developer",
        "publisher": "OpenAI",
        "description": "OpenAI Codex — AI coding assistant that runs in your terminal. Sends your prompts and code context to OpenAI's API while you use it. Multiple codex.exe instances are normal (one per active session). Currently ships without a signature, so the scanner flags that — it's legit, not malware. May also be installed as a per-user CLI at AppData\\Local\\OpenAI\\Codex\\bin\\…",
        "expected_paths": [
            r"WindowsApps\OpenAI.Codex",
            r"AppData\Local\Programs\Codex",
            r"AppData\Local\OpenAI\Codex",       # per-user CLI install
        ],
        "trust": "common",
    },
    "node_repl.exe": {
        "category": "Developer",
        "publisher": "OpenAI",
        "description": "Sandboxed Node.js REPL bundled with Codex — it's how Codex actually executes the tool calls it makes (running shell commands, reading files). Safe when launched by codex.exe; suspicious if running standalone.",
        "expected_paths": [r"AppData\Local\OpenAI\Codex"],
        "trust": "common",
    },
    "claude.exe": {
        "category": "Developer",
        "publisher": "Anthropic",
        "description": "Claude desktop app and Claude Code CLI — AI assistant by Anthropic. Sends your prompts to Anthropic's API while in use. Many instances are normal: each active Claude Code session and each desktop window is its own claude.exe. Safe to close any one; closes that session/window.",
        "expected_paths": [
            r"WindowsApps\Claude",                    # Microsoft Store install
            r"AppData\Local\Packages\Claude",         # per-user store data + Claude Code CLI lives here
            r"AppData\Local\AnthropicClaude",         # standalone installer
            r"AppData\Local\Programs\Claude",         # alternative installer location
        ],
        "trust": "common",
    },
    "cursor.exe": {
        "category": "Developer",
        "publisher": "Cursor",
        "description": "Cursor — VS Code fork with AI features baked in. Same multi-process Electron layout as VS Code. Sends code context to Cursor's servers (and from there to model providers) while AI features are in use; you can switch to 'privacy mode' in settings to opt out.",
        "expected_paths": [r"AppData\Local\Programs\cursor"],
        "trust": "common",
    },
    "windsurf.exe": {
        "category": "Developer",
        "publisher": "Codeium",
        "description": "Windsurf — AI code editor by Codeium, VS Code fork. Sends code context to Codeium's servers while AI features are active; an enterprise mode exists for keeping it local.",
        "expected_paths": [r"AppData\Local\Programs\Windsurf"],
        "trust": "common",
    },
    "ollama.exe": {
        "category": "Developer",
        "publisher": "Ollama",
        "description": "Ollama — runs large language models (Llama, Mistral, etc.) entirely locally on your PC. No prompts leave your machine. This is the CLI binary; the actual model lives in ollama_llama_server.exe. Closing ollama.exe stops any model you're chatting with.",
        "expected_paths": [r"AppData\Local\Programs\Ollama"],
        "trust": "common",
    },
    "ollama app.exe": {
        "category": "Developer",
        "publisher": "Ollama",
        "description": "The Ollama tray app — auto-starts an Ollama server on http://localhost:11434 in the background so other apps can use local LLMs without you opening a terminal. Closing the tray icon stops the server too.",
        "expected_paths": [r"AppData\Local\Programs\Ollama"],
        "trust": "common",
    },
    "ollama_llama_server.exe": {
        "category": "Developer",
        "publisher": "Ollama",
        "description": "The actual loaded LLM running in memory. Can easily use 4-30+ GB of RAM and most of your GPU VRAM depending on the model. Spawned when you run 'ollama run <model>'; closes itself after a few minutes of inactivity. Killing it just stops the model; ollama.exe will reload it on demand.",
        "expected_paths": [r"AppData\Local\Programs\Ollama"],
        "trust": "common",
    },
    "cowork-svc.exe": {
        "category": "Developer",
        "publisher": "Anthropic",
        "description": "A small Windows service installed by the Claude desktop app to coordinate state across multiple Claude Code sessions running in different terminals (the 'Cowork' feature). Idle most of the time. Safe to ignore — auto-restarts if killed.",
        "expected_paths": [
            r"WindowsApps\Claude",
            r"AppData\Local\Packages\Claude",
        ],
        "trust": "common",
    },

    # ---------- Windows Store / shell components Microsoft ships unsigned ----------
    # These show up as "unsigned" in catalog-aware checks because they ship with
    # ambient Windows trust rather than a per-binary signature. Listing them here
    # gives the user a description so they don't have to wonder.
    "textinputhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Hosts the on-screen touch keyboard and the handwriting / emoji panel (Win+H, Win+. shortcuts). Even on non-touch PCs it stays running to handle the emoji panel. Idle most of the time. Safe to close; Windows restarts it the next time you summon the keyboard.",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "crossdeviceresume.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Powers the Windows 11 'Continue on another device' feature — when you're signed in to the same Microsoft account on your phone and PC, this is what lets you pick up Edge tabs or recent files. Phones home to Microsoft. Safe to disable in Settings → System → Cross-device experiences if you don't use it.",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "aggregatorhost.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Aggregates sensor and location data (light, motion, GPS where available) for Windows apps that request it. Most desktops don't have sensors so it's idle. Leave it; Windows manages it.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "unsecapp.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "WMI Asynchronous Callback Receiver — the channel that delivers system-event notifications back to programs that subscribed (antivirus, monitoring scripts, etc.). Idle until something fires a callback. Don't close it; it's needed by anything using WMI events.",
        "expected_paths": [r"C:\Windows\System32\wbem"],
        "trust": "trusted",
    },
    "widgetservice.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Background service that fetches weather, news, traffic, and stocks for the Windows 11 Widgets panel (click the weather icon on the taskbar). Phones home for content. You can hide the Widgets icon from the taskbar to silence it.",
        "expected_paths": [r"C:\Program Files\WindowsApps\Microsoft.WidgetsPlatformRuntime"],
        "trust": "trusted",
    },
    "widgets.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Renders the Widgets panel UI when you click the weather icon on the taskbar. Safe to close; reopens the next time you click the icon.",
        "expected_paths": [r"C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience"],
        "trust": "trusted",
    },
    "searchapp.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Older name for the Windows search bar UI (now SearchHost.exe on Win11).",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },

    # ---------- WSL / virtualisation ----------
    "wslhost.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Helper process for Windows Subsystem for Linux distributions.",
        "expected_paths": [r"C:\Windows\System32\lxss"],
        "trust": "trusted",
    },
    "wslservice.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Windows Subsystem for Linux service. Manages WSL2 utility VMs.",
        "expected_paths": [r"C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux"],
        "trust": "trusted",
    },
    "vmcompute.exe": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Hyper-V Host Compute Service. Powers WSL2, Windows Sandbox, and Docker Desktop's Linux VM.",
        "expected_paths": [SYS32],
        "trust": "trusted",
    },
    "vmmem": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Memory reservation for a running Hyper-V VM (WSL2, sandbox, Docker). High memory here is from your Linux processes inside the VM.",
        "expected_paths": [],
        "trust": "trusted",
    },
    "vmmemwsl": {
        "category": "Developer",
        "publisher": "Microsoft",
        "description": "Memory reservation for WSL2's utility VM. High RAM here is from your Linux processes.",
        "expected_paths": [],
        "trust": "trusted",
    },

    # ---------- Adobe ----------
    "acrord32.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe Acrobat Reader (32-bit) — PDF viewer.",
        "expected_paths": [r"C:\Program Files (x86)\Adobe", r"C:\Program Files\Adobe"],
        "trust": "common",
    },
    "acrobat.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe Acrobat — PDF editor.",
        "expected_paths": [r"C:\Program Files\Adobe", r"C:\Program Files (x86)\Adobe"],
        "trust": "common",
    },
    "adobeupdateservice.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe Update Service.",
        "expected_paths": [r"C:\Program Files (x86)\Common Files\Adobe"],
        "trust": "common",
    },
    "jusched.exe": {
        "category": "Productivity",
        "publisher": "Oracle",
        "description": "Java Update Scheduler — silently checks for Java runtime updates in the background. Doesn't do anything else. Safe to disable in services.msc if you never use Java apps. Often left behind when Java is no longer needed.",
        "expected_paths": [r"C:\Program Files\Common Files\Java", r"C:\Program Files (x86)\Common Files\Java"],
        "trust": "common",
    },

    # ---------- Common silent auto-updaters (almost everyone has these) ----------
    "googleupdate.exe": {
        "category": "Utility",
        "publisher": "Google",
        "description": "Background updater for Chrome and other Google apps. Runs on a schedule (usually daily) and quietly downloads/installs updates. Safe to close; it'll wake up again on its next scheduled run. Disabling it means you have to manually update Chrome.",
        "expected_paths": [r"C:\Program Files (x86)\Google\Update", r"C:\Program Files\Google\Update"],
        "trust": "common",
    },
    "googleupdater.exe": {
        "category": "Utility",
        "publisher": "Google",
        "description": "Newer Google Updater (replaces GoogleUpdate.exe) — same job, updated under the hood. Quietly keeps Chrome and friends current.",
        "expected_paths": [r"AppData\Local\Google\GoogleUpdater"],
        "trust": "common",
    },
    "googlecrashhandler.exe": {
        "category": "Utility",
        "publisher": "Google",
        "description": "Crash reporter bundled with Google Update. Sends crash dumps to Google if a Google product crashes. Only active during a crash event.",
        "expected_paths": [r"C:\Program Files (x86)\Google\Update", r"C:\Program Files\Google\Update"],
        "trust": "common",
    },
    "googlecrashhandler64.exe": {
        "category": "Utility",
        "publisher": "Google",
        "description": "64-bit version of GoogleCrashHandler — see GoogleCrashHandler.exe.",
        "expected_paths": [r"C:\Program Files (x86)\Google\Update", r"C:\Program Files\Google\Update"],
        "trust": "common",
    },
    "microsoftedgeupdate.exe": {
        "category": "Utility",
        "publisher": "Microsoft",
        "description": "Background updater for Microsoft Edge — same job as GoogleUpdate but for Edge. Runs on a schedule, downloads and installs Edge updates silently.",
        "expected_paths": [r"C:\Program Files (x86)\Microsoft\EdgeUpdate", r"C:\Program Files\Microsoft\EdgeUpdate"],
        "trust": "trusted",
    },
    "adobearm.exe": {
        "category": "Utility",
        "publisher": "Adobe",
        "description": "Adobe Acrobat Updater — checks for and installs updates for Acrobat Reader and Acrobat Pro. Can be slow and chatty. Disable via Acrobat → Preferences → Updater if it annoys you.",
        "expected_paths": [r"C:\Program Files (x86)\Common Files\Adobe\ARM", r"C:\Program Files\Common Files\Adobe\ARM"],
        "trust": "common",
    },
    "jucheck.exe": {
        "category": "Utility",
        "publisher": "Oracle",
        "description": "Java updater run by jusched.exe. Pops up to install Java updates. Closes itself when done.",
        "expected_paths": [r"C:\Program Files\Common Files\Java", r"C:\Program Files (x86)\Common Files\Java"],
        "trust": "common",
    },

    # ---------- Adobe Creative Cloud ----------
    "creative cloud.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe Creative Cloud desktop app — manages installs/updates of Photoshop, Illustrator, Premiere, etc. Auto-starts at login and stays in the tray. Heavy on RAM. Safe to quit when you're not actively installing or updating an Adobe app.",
        "expected_paths": [r"C:\Program Files\Adobe\Adobe Creative Cloud", r"C:\Program Files (x86)\Adobe\Adobe Creative Cloud"],
        "trust": "common",
    },
    "ccxprocess.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe Creative Cloud Experience — drives the home/learn tabs and the in-app notifications in Creative Cloud. Background helper for the CC desktop app.",
        "expected_paths": [r"C:\Program Files\Common Files\Adobe", r"C:\Program Files (x86)\Common Files\Adobe"],
        "trust": "common",
    },
    "adobeipcbroker.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Inter-process communication broker between Adobe apps (Photoshop ↔ Creative Cloud ↔ Lightroom, etc.). Mostly idle.",
        "expected_paths": [r"C:\Program Files\Common Files\Adobe", r"C:\Program Files (x86)\Common Files\Adobe"],
        "trust": "common",
    },
    "adobe desktop service.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Background service for Creative Cloud installs, font sync, and library access. Required for Creative Cloud to function.",
        "expected_paths": [r"C:\Program Files\Common Files\Adobe", r"C:\Program Files (x86)\Common Files\Adobe"],
        "trust": "common",
    },
    "coresync.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe CoreSync — syncs Creative Cloud Files folder to cloud. Like OneDrive but for Adobe's cloud storage. Only useful if you actually use CC Files.",
        "expected_paths": [r"C:\Program Files\Adobe\Adobe Creative Cloud Experience", r"AppData\Local\Adobe"],
        "trust": "common",
    },
    "cclibrary.exe": {
        "category": "Productivity",
        "publisher": "Adobe",
        "description": "Adobe Creative Cloud Libraries — syncs shared design assets (colours, brushes, character styles) across Adobe apps and team members.",
        "expected_paths": [r"C:\Program Files\Common Files\Adobe", r"C:\Program Files (x86)\Common Files\Adobe"],
        "trust": "common",
    },

    # ---------- More NVIDIA helpers commonly seen ----------
    "nvsphelper64.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "NVIDIA helper process for system services. Component of the NVIDIA Display driver. Safe to leave alone.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation", r"C:\Windows\System32"],
        "trust": "common",
    },
    "nvfvsdksvc_x64.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "NVIDIA FrameView SDK service — powers per-game performance overlays (FPS, frame time, GPU power draw). Spawns nvrla.exe and PresentMon helpers. Safe to close if you don't use performance overlays.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation\FrameViewSDK"],
        "trust": "common",
    },
    "nvrla.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "NVIDIA Real-time Latency Analyzer — collects latency data for FrameView/Reflex overlays. Spawned by nvfvsdksvc_x64.exe. Only useful while gaming with the overlay on.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation\FrameViewSDK"],
        "trust": "common",
    },
    "presentmon_x64.exe": {
        "category": "Drivers",
        "publisher": "Intel / NVIDIA",
        "description": "PresentMon — Intel's open-source GPU frame-pacing telemetry tool, bundled into NVIDIA FrameView for FPS measurement. Active during gaming overlays.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation\FrameViewSDK"],
        "trust": "common",
    },
    "fvcontainer.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "NVIDIA FrameView container — hosts FrameView's UI components. Part of the FrameView gaming overlay suite.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation\FrameViewSDK"],
        "trust": "common",
    },
    "fvcontainer.system.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "FrameView system-level container — runs the parts of FrameView that need elevated access to GPU telemetry.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation\FrameViewSDK"],
        "trust": "common",
    },
    "nvidia overlay.exe": {
        "category": "Drivers",
        "publisher": "NVIDIA",
        "description": "The NVIDIA App overlay (formerly GeForce Experience overlay). Press Alt+Z to bring it up. Each open game can have its own overlay instance, so multiple are normal.",
        "expected_paths": [r"C:\Program Files\NVIDIA Corporation\NVIDIA App"],
        "trust": "common",
    },

    # ---------- Corsair iCUE helpers ----------
    "corsaircpuidservice.exe": {
        "category": "Drivers",
        "publisher": "Corsair",
        "description": "Corsair iCUE CPU detection service — reads CPU info for the iCUE temperature/performance widgets.",
        "expected_paths": [r"C:\Program Files\Corsair"],
        "trust": "common",
    },

    # ---------- Steam extras ----------
    "gameoverlayui.exe": {
        "category": "Gaming",
        "publisher": "Valve",
        "description": "Steam in-game overlay — press Shift+Tab while playing a Steam game to open it. Lets you chat, browse the web, see achievements without alt-tabbing. Closing it disables the overlay until you restart the game.",
        "expected_paths": [r"C:\Program Files (x86)\Steam", r"C:\Program Files\Steam"],
        "trust": "common",
    },
    "gameoverlayui64.exe": {
        "category": "Gaming",
        "publisher": "Valve",
        "description": "64-bit Steam in-game overlay — see gameoverlayui.exe.",
        "expected_paths": [r"C:\Program Files (x86)\Steam", r"C:\Program Files\Steam"],
        "trust": "common",
    },

    # ---------- Win10-specific that don't exist on Win11 ----------
    "searchui.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Windows 10's search & Cortana UI process — predecessor to Win11's SearchHost.exe. Renders the taskbar search and the Cortana panel. Safe to close; reopens on next click.",
        "expected_paths": [r"C:\Windows\SystemApps"],
        "trust": "trusted",
    },
    "cortana.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Microsoft's voice assistant — mostly deprecated on Win11, still present on Win10. Listens for 'Hey Cortana' if you've enabled it; otherwise idle. Safe to disable in Settings if you don't use it.",
        "expected_paths": [r"C:\Windows\SystemApps", r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "stikynot.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Legacy Sticky Notes (Win7/Win8 era), occasionally still present on Win10. The modern replacement is Microsoft.Notes.exe / the Sticky Notes Store app. Safe to close.",
        "expected_paths": [r"C:\Windows"],
        "trust": "trusted",
    },
    "snippingtool.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Snipping Tool — built-in screenshot tool (Win+Shift+S triggers a quick capture). Modern Win11 version handles screen recording too. Idle when not capturing.",
        "expected_paths": [SYS32, r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "screensketch.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Snip & Sketch (older name) — built-in screenshot tool, eventually merged back into Snipping Tool. Triggered by Win+Shift+S.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
    "systemsettings.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "The Windows Settings app. Opens when you hit Win+I. Closing it just closes the Settings window.",
        "expected_paths": [r"C:\Windows\ImmersiveControlPanel"],
        "trust": "trusted",
    },
    "msascuil.exe": {
        "category": "Security",
        "publisher": "Microsoft",
        "description": "Old Microsoft Security Client UI process (predecessor of Windows Security). Mostly retired but occasionally hangs around on upgraded Win10 PCs.",
        "expected_paths": [r"C:\Program Files\Microsoft Security Client"],
        "trust": "trusted",
    },

    # ---------- VTube / streaming tools commonly used ----------
    "vtube studio.exe": {
        "category": "Media",
        "publisher": "Denchi Soft",
        "description": "VTube Studio — desktop app that turns your webcam into a Live2D avatar for streaming (used by VTubers). Ships unsigned, which is why our scanner notes it. Closing it stops the avatar; safe.",
        "expected_paths": [r"steamapps\common\VTube Studio", r"AppData\Local"],
        "trust": "common",
    },
    "unitycrashhandler64.exe": {
        "category": "Utility",
        "publisher": "Unity Technologies",
        "description": "Unity game-engine crash handler. Ships bundled inside every Unity-built game (VTube Studio, Among Us, Cuphead, thousands more). Only activates if the parent game crashes. Check the parent folder to see which Unity game owns it.",
        "expected_paths": [],   # ships inside many games
        "trust": "common",
    },

    # ---------- Wallpaper engines ----------
    "wallpaper32.exe": {
        "category": "Utility",
        "publisher": "Wallpaper Engine",
        "description": "Wallpaper Engine (32-bit) — animated desktop backgrounds via Steam. 32-bit version for older systems; high CPU/GPU is normal if your wallpaper is animated.",
        "expected_paths": [r"steamapps\common\wallpaper_engine"],
        "trust": "common",
    },
    "lively.exe": {
        "category": "Utility",
        "publisher": "Lively Wallpaper",
        "description": "Lively Wallpaper — free open-source alternative to Wallpaper Engine. Lives in the system tray. Closing it stops the animated wallpaper until you restart Lively.",
        "expected_paths": [r"AppData\Local\Programs\Lively", r"C:\Program Files\WindowsApps"],
        "trust": "common",
    },

    # ---------- OEM helpers (laptop / desktop bundled software) ----------
    "easytuneengineservice.exe": {
        "category": "Drivers",
        "publisher": "GIGABYTE",
        "description": "GIGABYTE EasyTune engine — backs the EasyTune CPU/fan tuning utility for GIGABYTE motherboards. Runs as a service. Only needed if you actively use EasyTune to overclock.",
        "expected_paths": [r"C:\Program Files (x86)\GIGABYTE"],
        "trust": "common",
    },
    "amdrsserv.exe": {
        "category": "Drivers",
        "publisher": "AMD",
        "description": "AMD Radeon Software service — backs the Radeon control panel (right-click desktop → AMD Software). Auto-starts at boot. Only present if you have an AMD GPU.",
        "expected_paths": [r"C:\Program Files\AMD"],
        "trust": "common",
    },
    "amdrssrcext.exe": {
        "category": "Drivers",
        "publisher": "AMD",
        "description": "AMD Radeon Software resource helper. Handles in-game overlays and capture for AMD GPUs.",
        "expected_paths": [r"C:\Program Files\AMD"],
        "trust": "common",
    },

    # ---------- Bluetooth / input ----------
    "tabtip.exe": {
        "category": "Windows Core",
        "publisher": "Microsoft",
        "description": "Touch keyboard / handwriting panel — alternative input methods. Starts on demand when an app requests touch input. Safe to close; it'll come back when needed.",
        "expected_paths": [r"C:\Program Files\Common Files\microsoft shared\ink"],
        "trust": "trusted",
    },
    "bluetoothnotificationagent.exe": {
        "category": "Drivers",
        "publisher": "Realtek / Microsoft",
        "description": "Bluetooth tray notification helper — pops a balloon when a Bluetooth device connects/disconnects. Idle most of the time.",
        "expected_paths": [SYS32, r"C:\Program Files\Common Files"],
        "trust": "common",
    },

    # ---------- Common installer / setup paths ----------
    "ovrservicelauncher.exe": {
        "category": "Gaming",
        "publisher": "Meta",
        "description": "Bootstraps OVRServer_x64.exe — the Meta / Oculus VR runtime. Runs briefly at startup or whenever the Oculus app launches, then exits.",
        "expected_paths": [r"C:\Program Files\Oculus", r"C:\Program Files\Meta Horizon"],
        "trust": "common",
    },

    # ---------- Crash handlers (very common across Chromium / Electron apps) ----------
    "crashpad_handler.exe": {
        "category": "Utility",
        "publisher": "Various (Chromium-based apps)",
        "description": "Crashpad — Google's crash-reporting helper, bundled with most Chromium-based apps (Chrome, Edge, Discord, Slack, VS Code, Codex, etc). Check the parent folder to see which app owns it.",
        "expected_paths": [],   # ships inside many apps; path varies
        "trust": "common",
    },
    "mqrdcrashpadhandler.exe": {
        "category": "Utility",
        "publisher": "Meta",
        "description": "Crashpad handler for Meta Quest Remote Desktop. Reports crashes; runs only if Remote Desktop is installed.",
        "expected_paths": [r"C:\Program Files\Meta Horizon"],
        "trust": "common",
    },

    # ---------- OEM / hardware ----------
    "gbt_dl_lib.exe": {
        "category": "Drivers",
        "publisher": "Gigabyte",
        "description": "Gigabyte motherboard helper — used by Gigabyte Control Center / RGB Fusion / similar GBT software.",
        "expected_paths": [r"C:\Program Files\WindowsApps", r"C:\Program Files\GIGABYTE"],
        "trust": "common",
    },
    "igfxcuiservice.exe": {
        "category": "Drivers",
        "publisher": "Intel",
        "description": "Intel HD Graphics control panel service.",
        "expected_paths": [SYS32],
        "trust": "common",
    },
    "lms.exe": {
        "category": "Drivers",
        "publisher": "Intel",
        "description": "Intel Local Management Service — part of Intel Management Engine on business laptops.",
        "expected_paths": [r"C:\Program Files (x86)\Intel\Intel(R) Management Engine Components"],
        "trust": "common",
    },
    "armourycrate.userssessionhelper.exe": {
        "category": "Drivers",
        "publisher": "ASUS",
        "description": "ASUS Armoury Crate — RGB / fan / system tuning for ASUS hardware.",
        "expected_paths": [r"C:\Program Files\ASUS"],
        "trust": "common",
    },
    "hwinfo64.exe": {
        "category": "Utility",
        "publisher": "Martin Malik (REALiX)",
        "description": "HWiNFO64 — detailed hardware information and monitoring.",
        "expected_paths": [r"C:\Program Files\HWiNFO64"],
        "trust": "common",
    },
    "afterburner.exe": {
        "category": "Utility",
        "publisher": "MSI",
        "description": "MSI Afterburner — GPU overclocking and monitoring (works with any GPU brand, not just MSI).",
        "expected_paths": [r"C:\Program Files (x86)\MSI Afterburner"],
        "trust": "common",
    },
    "rtss.exe": {
        "category": "Utility",
        "publisher": "Guru3D",
        "description": "RivaTuner Statistics Server — FPS overlay, paired with MSI Afterburner.",
        "expected_paths": [r"C:\Program Files (x86)\RivaTuner Statistics Server"],
        "trust": "common",
    },

    # ---------- VR / peripherals ----------
    "remotedesktopcompanion.exe": {
        "category": "Communication",
        "publisher": "Meta",
        "description": "Meta Quest Remote Desktop companion — lets you mirror your PC to a Quest headset.",
        "expected_paths": [r"C:\Program Files\Meta Horizon"],
        "trust": "common",
    },
    "ovrserver_x64.exe": {
        "category": "Gaming",
        "publisher": "Meta",
        "description": "Oculus / Meta VR runtime service — handles headset tracking, rendering, and SteamVR bridging for a Quest tethered to PC over Link or Air Link. Auto-starts whenever Meta Horizon / Oculus is installed; closing it kills any active VR session. Idle when no headset is connected.",
        "expected_paths": [r"C:\Program Files\Oculus", r"C:\Program Files\Meta Horizon"],
        "trust": "common",
    },
    "oculusclient.exe": {
        "category": "Gaming",
        "publisher": "Meta",
        "description": "Oculus / Meta desktop app — manages installed VR games and headset settings.",
        "expected_paths": [r"C:\Program Files\Oculus"],
        "trust": "common",
    },

    # ---------- Antivirus / security services (often protected so we can't read metadata) ----------
    "nortonsvc.exe": {
        "category": "Security",
        "publisher": "Gen Digital",
        "description": "Norton 360 service — the background process for Norton antivirus / security suite.",
        "expected_paths": [r"C:\Program Files\Norton"],
        "trust": "common",
    },
    "nortonsecurity.exe": {
        "category": "Security",
        "publisher": "Gen Digital",
        "description": "Norton Security engine — backs the Norton antivirus scanner.",
        "expected_paths": [r"C:\Program Files\Norton"],
        "trust": "common",
    },
    "asweng.exe": {
        "category": "Security",
        "publisher": "Avast",
        "description": "Avast antivirus engine.",
        "expected_paths": [r"C:\Program Files\AVAST", r"C:\Program Files\Avast"],
        "trust": "common",
    },
    "aswengsrv.exe": {
        "category": "Security",
        "publisher": "Avast / Gen Digital",
        "description": "Avast antivirus engine service. Gen Digital (which owns Avast, AVG, and Norton) bundles this same engine into Norton 360 too, so you may see it under either C:\\Program Files\\AVAST or C:\\Program Files\\Norton\\Suite.",
        "expected_paths": [r"C:\Program Files\AVAST", r"C:\Program Files\Avast", r"C:\Program Files\Norton\Suite"],
        "trust": "common",
    },
    "aswidsagent.exe": {
        "category": "Security",
        "publisher": "Avast / Gen Digital",
        "description": "Avast Behaviour Shield — monitors running processes for suspicious activity (file modifications, registry edits, network use). Bundled into Norton 360 too via Gen Digital. Don't close it; it'll restart and leave you briefly unprotected.",
        "expected_paths": [r"C:\Program Files\AVAST", r"C:\Program Files\Avast", r"C:\Program Files\Norton\Suite"],
        "trust": "common",
    },
    "avastui.exe": {
        "category": "Security",
        "publisher": "Avast",
        "description": "Avast antivirus user interface.",
        "expected_paths": [r"C:\Program Files\AVAST", r"C:\Program Files\Avast"],
        "trust": "common",
    },
    "avgui.exe": {
        "category": "Security",
        "publisher": "AVG",
        "description": "AVG antivirus user interface.",
        "expected_paths": [r"C:\Program Files\AVG"],
        "trust": "common",
    },
    "mbamservice.exe": {
        "category": "Security",
        "publisher": "Malwarebytes",
        "description": "Malwarebytes Anti-Malware service — the background scanner.",
        "expected_paths": [r"C:\Program Files\Malwarebytes"],
        "trust": "common",
    },
    "mbamtray.exe": {
        "category": "Security",
        "publisher": "Malwarebytes",
        "description": "Malwarebytes tray icon — minimizes the UI to the notification area.",
        "expected_paths": [r"C:\Program Files\Malwarebytes"],
        "trust": "common",
    },
    "mcshield.exe": {
        "category": "Security",
        "publisher": "McAfee",
        "description": "McAfee Shield — real-time antivirus scanner.",
        "expected_paths": [r"C:\Program Files\McAfee"],
        "trust": "common",
    },
    "mcuicnt.exe": {
        "category": "Security",
        "publisher": "McAfee",
        "description": "McAfee UI launcher.",
        "expected_paths": [r"C:\Program Files\McAfee"],
        "trust": "common",
    },
    "bdservicehost.exe": {
        "category": "Security",
        "publisher": "Bitdefender",
        "description": "Bitdefender service host.",
        "expected_paths": [r"C:\Program Files\Bitdefender"],
        "trust": "common",
    },
    "avp.exe": {
        "category": "Security",
        "publisher": "Kaspersky",
        "description": "Kaspersky antivirus main process.",
        "expected_paths": [r"C:\Program Files (x86)\Kaspersky"],
        "trust": "common",
    },
    "ekrn.exe": {
        "category": "Security",
        "publisher": "ESET",
        "description": "ESET kernel service — the antivirus engine.",
        "expected_paths": [r"C:\Program Files\ESET"],
        "trust": "common",
    },
    "nlltoolssvc.exe": {
        "category": "Security",
        "publisher": "Gen Digital",
        "description": "Norton LifeLock identity-protection service (part of Norton 360).",
        "expected_paths": [r"C:\Program Files\Norton", r"C:\ProgramData\NortonLifeLock"],
        "trust": "common",
    },
    "vrserver.exe": {
        "category": "Gaming",
        "publisher": "Valve",
        "description": "SteamVR server — runs while a VR headset is connected.",
        "expected_paths": [r"C:\Program Files (x86)\Steam\steamapps\common\SteamVR"],
        "trust": "common",
    },
    "opentabletdriver.daemon.exe": {
        "category": "Drivers",
        "publisher": "OpenTabletDriver",
        "description": "OpenTabletDriver — open-source driver for drawing tablets (Wacom alternative).",
        "expected_paths": [r"AppData\Local\OpenTabletDriver"],
        "trust": "common",
    },
    "wallpaper64.exe": {
        "category": "Utility",
        "publisher": "Wallpaper Engine",
        "description": "Wallpaper Engine — animated desktop backgrounds.",
        "expected_paths": [r"steamapps\common\wallpaper_engine"],
        "trust": "common",
    },

    # ---------- Win11 system apps (catalog-signed, common to see) ----------
    "phone.exe": {
        "category": "Communication",
        "publisher": "Microsoft",
        "description": "Phone Link / Your Phone — Windows app that mirrors your Android phone.",
        "expected_paths": [r"C:\Program Files\WindowsApps\Microsoft.YourPhone"],
        "trust": "trusted",
    },
    "yourphone.exe": {
        "category": "Communication",
        "publisher": "Microsoft",
        "description": "Phone Link / Your Phone (older name) — mirrors your Android phone to Windows.",
        "expected_paths": [r"C:\Program Files\WindowsApps\Microsoft.YourPhone"],
        "trust": "trusted",
    },
    "video.ui.exe": {
        "category": "Media",
        "publisher": "Microsoft",
        "description": "Windows Movies & TV app UI.",
        "expected_paths": [r"C:\Program Files\WindowsApps\Microsoft.ZuneVideo"],
        "trust": "trusted",
    },
    "microsoft.media.player.exe": {
        "category": "Media",
        "publisher": "Microsoft",
        "description": "Windows Media Player (Windows 11 redesign).",
        "expected_paths": [r"C:\Program Files\WindowsApps\Microsoft.ZuneMusic"],
        "trust": "trusted",
    },
    "calculator.exe": {
        "category": "Productivity",
        "publisher": "Microsoft",
        "description": "Windows Calculator.",
        "expected_paths": [r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator"],
        "trust": "trusted",
    },
    "msteamssettings.exe": {
        "category": "Communication",
        "publisher": "Microsoft",
        "description": "Microsoft Teams (new) settings UI helper.",
        "expected_paths": [r"C:\Program Files\WindowsApps"],
        "trust": "trusted",
    },
}


# Suspicious name patterns that masquerade as system processes. If we see a process
# with one of these names running from anywhere other than the expected path, that's
# a strong red flag.
SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "explorer.exe", "spoolsv.exe",
    "taskhostw.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe",
    "rundll32.exe", "dllhost.exe", "sihost.exe", "audiodg.exe",
    "lsm.exe", "userinit.exe", "logonui.exe",
}


# Folders that legitimate software rarely runs from. A process executing from one
# of these is worth a closer look (but not automatically malicious).
SUSPICIOUS_PATH_FRAGMENTS = [
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\windows\temp",
    r"\temp\\",
    r"\$recycle.bin",
    r"\users\public\\",
    r"\programdata\\temp",
    r"\downloads\\",
    r"\onedrive\\",  # mild — sync folder shouldn't run executables
]


# Command-line fragments commonly seen in living-off-the-land attacks.
SUSPICIOUS_CMDLINE_FRAGMENTS = [
    " -enc ",       # PowerShell encoded command
    " -encodedcommand",
    " -e jab",      # encoded payload pattern
    " /c start http",
    "iex(",         # Invoke-Expression
    "invoke-expression",
    "downloadstring(",
    "downloadfile(",
    "frombase64string(",
    "-windowstyle hidden",
    "-w hidden",
    "-nop -w hidden",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "certutil -decode",
    "regsvr32 /s /n /u /i:http",
    "mshta http",
    "mshta vbscript:",
    "wscript //e:jscript",
]


def lookup(name: str):
    """Look up a process by name (case-insensitive). Returns None if unknown."""
    if not name:
        return None
    return PROCESS_DB.get(name.lower())


# Maps publisher-name substrings (case-insensitive) to a one-sentence
# "what this company makes" hint, so that even unknown binaries from known
# publishers get a useful purpose line. We match substrings rather than exact
# names because publishers sign as "Microsoft", "Microsoft Corporation",
# "Microsoft Windows", etc. — different strings, same purpose.
#
# Keys must be lowercase. The most specific keys win — see purpose_for() below.
PUBLISHER_PURPOSE: dict[str, str] = {
    # ---------- Antivirus & security ----------
    "norton":              "Part of Norton antivirus / security suite.",
    "symantec":            "Part of Symantec / Norton antivirus.",
    "gen digital":         "Gen Digital publishes Norton, Avast, and AVG antivirus.",
    "nortonlifelock":      "Norton (Gen Digital's antivirus brand).",
    "mcafee":              "This is McAfee antivirus / security software.",
    "avast":               "This is Avast antivirus.",
    "avg technologies":    "This is AVG antivirus.",
    "avira":               "This is Avira antivirus.",
    "bitdefender":         "This is Bitdefender antivirus.",
    "kaspersky":           "This is Kaspersky antivirus.",
    "eset":                "This is ESET antivirus.",
    "trend micro":         "This is Trend Micro antivirus.",
    "malwarebytes":        "This is Malwarebytes anti-malware.",
    "sophos":              "This is Sophos endpoint security.",
    "webroot":             "This is Webroot antivirus.",
    "f-secure":            "This is F-Secure antivirus.",
    "panda security":      "This is Panda antivirus.",

    # ---------- Graphics drivers ----------
    "nvidia":              "Part of NVIDIA's graphics drivers and GeForce utilities.",
    "advanced micro devices": "Part of AMD's graphics or CPU drivers.",
    "amd":                 "Part of AMD's graphics or CPU drivers.",
    "ati technologies":    "Legacy ATI/AMD graphics driver component.",

    # ---------- Audio / Intel / hardware ----------
    "realtek":             "Realtek audio or networking driver.",
    "intel corporation":   "Part of Intel's hardware drivers or utilities.",
    "intel(r)":            "Part of Intel's hardware drivers or utilities.",
    "creative technology": "Sound Blaster audio driver/utility.",

    # ---------- Peripherals (mice, keyboards, headsets, webcams) ----------
    "logitech":            "Drives Logitech mice, keyboards, webcams, or headsets.",
    "logi ":               "Drives Logitech / Logi peripherals.",
    "razer":               "Razer gaming peripheral / Synapse software.",
    "corsair":             "Corsair iCUE — gaming peripherals and RGB.",
    "steelseries":         "SteelSeries peripheral software.",
    "hyperx":              "HyperX peripheral / NGENUITY software.",
    "elgato":              "Elgato streaming / capture hardware software.",
    "wacom":               "Wacom drawing tablet driver.",

    # ---------- OEM motherboard / laptop utilities ----------
    "asustek":             "ASUS motherboard / laptop utility.",
    "asus":                "ASUS hardware utility (Armoury Crate etc.).",
    "micro-star":          "MSI motherboard / laptop utility.",
    "gigabyte":            "GIGABYTE motherboard utility (Control Center, RGB Fusion, etc.).",
    "giga-byte":           "GIGABYTE motherboard utility (Control Center, RGB Fusion, etc.).",
    "asrock":              "ASRock motherboard utility.",
    "dell":                "Dell-installed system utility.",
    "hewlett-packard":     "HP-installed system utility.",
    "hp inc":              "HP-installed system utility.",
    "lenovo":              "Lenovo-installed system utility.",
    "acer":                "Acer-installed system utility.",
    "samsung":             "Samsung-installed utility (often Magician for SSDs).",

    # ---------- Gaming launchers / anti-cheat ----------
    "valve":               "Valve / Steam game platform.",
    "epic games":           "Epic Games Store launcher / engine runtime.",
    "blizzard":            "Battle.net launcher for Blizzard games.",
    "riot games":          "Riot launcher (League/Valorant) or Vanguard anti-cheat.",
    "electronic arts":     "EA App game launcher.",
    "ubisoft":             "Ubisoft Connect launcher.",
    "rockstar games":      "Rockstar Games Launcher.",
    "gog ":                "GOG Galaxy game launcher.",
    "easyanticheat":       "EasyAntiCheat — anti-cheat used by many multiplayer games.",
    "battleye":            "BattlEye anti-cheat used by many multiplayer games.",

    # ---------- Productivity / creative ----------
    "adobe":               "Adobe Creative Cloud or Acrobat component.",
    "autodesk":            "Autodesk creative software (AutoCAD, Maya, Fusion 360).",
    "jetbrains":           "JetBrains IDE (IntelliJ, PyCharm, WebStorm, etc.).",
    "github":              "GitHub Desktop / CLI tooling.",
    "atlassian":           "Atlassian product (Jira, Confluence, Bitbucket helpers).",

    # ---------- Communication ----------
    "discord inc":         "Discord — chat, voice, and video for communities.",
    "slack technologies":  "Slack workplace messaging.",
    "zoom video":          "Zoom video conferencing.",
    "telegram":            "Telegram messenger.",
    "whatsapp":            "WhatsApp messenger.",
    "signal":              "Signal secure messenger.",

    # ---------- Cloud sync / storage ----------
    "dropbox":             "Dropbox file-sync client.",
    "microsoft onedrive":  "OneDrive file-sync.",
    "spideroak":           "SpiderOak encrypted backup.",
    "backblaze":           "Backblaze online backup.",
    "mega ":               "MEGA encrypted cloud sync.",

    # ---------- VPN / privacy ----------
    "nordvpn":             "NordVPN client.",
    "expressvpn":          "ExpressVPN client.",
    "protonvpn":           "ProtonVPN client.",
    "mullvad":             "Mullvad VPN client.",
    "private internet access": "PIA VPN client.",
    "wireguard":           "WireGuard VPN client.",
    "openvpn":             "OpenVPN client.",
    "cisco systems":       "Cisco corporate VPN or networking software.",
    "fortinet":            "Fortinet corporate security / VPN.",

    # ---------- Remote access ----------
    "teamviewer":          "TeamViewer remote access / support tool.",
    "anydesk":             "AnyDesk remote desktop tool.",
    "splashtop":           "Splashtop remote desktop.",
    "logmein":             "LogMeIn remote access.",

    # ---------- Media / streaming ----------
    "spotify":             "Spotify music streaming.",
    "videolan":            "VLC media player.",
    "obs project":         "OBS Studio — streaming and recording.",
    "streamlabs":          "Streamlabs streaming software.",
    "plex":                "Plex media server / client.",
    "jellyfin":            "Jellyfin media server.",
    "audacity":            "Audacity audio editor.",

    # ---------- Browsers ----------
    "google llc":          "Google product (Chrome, Drive, Workspace tools).",
    "google inc":          "Google product (Chrome, Drive, Workspace tools).",
    "mozilla":             "Mozilla Firefox / Thunderbird.",
    "brave software":      "Brave web browser.",
    "vivaldi":             "Vivaldi web browser.",
    "opera software":      "Opera web browser.",

    # ---------- AI / dev tools ----------
    "openai":              "OpenAI tooling (Codex, ChatGPT desktop, etc.).",
    "anthropic":           "Anthropic — makers of Claude AI assistant.",
    "ollama":              "Ollama — runs large language models locally on your PC.",
    "github copilot":      "GitHub Copilot AI coding assistant.",

    # ---------- VR / hardware vendors ----------
    "facebook technologies": "Meta Quest / Oculus VR runtime and tooling.",
    "meta platforms":      "Meta (Facebook) — VR, messaging, or social platform tooling.",
    "oculus":              "Meta Quest / Oculus VR software.",
    "valve corporation":   "Valve / Steam game platform or SteamVR.",

    # ---------- Microsoft (catch-all for misc Microsoft binaries) ----------
    "microsoft":           "Part of Windows or another Microsoft product.",

    # ---------- Misc utilities ----------
    "voidtools":           "Everything — instant file search.",
    "rivatuner":           "RivaTuner Statistics Server (RTSS) — FPS overlay.",
    "guru3d":              "Guru3D utility — usually MSI Afterburner companion.",
    "open broadcaster":    "OBS Studio component.",
    "realix":              "HWiNFO — detailed hardware monitoring.",
    "piriform":            "CCleaner / Piriform utility.",
    "igor pavlov":         "7-Zip archive manager.",
    "rarlab":              "WinRAR archive manager.",
    "notepad++":           "Notepad++ text editor.",
    "vlc":                 "VLC media player.",
    "audacity":            "Audacity audio editor.",
}


def purpose_for(publisher: str) -> str:
    """Return a one-line 'what this publisher makes' hint, or '' if we don't
    have one. Matches publisher-name substrings case-insensitively. When
    multiple keys match, the *longest* key wins so 'gen digital' beats a
    hypothetical shorter match."""
    if not publisher:
        return ""
    pub_lower = publisher.lower()
    matched_key = ""
    matched_value = ""
    for key, value in PUBLISHER_PURPOSE.items():
        if key in pub_lower and len(key) > len(matched_key):
            matched_key = key
            matched_value = value
    return matched_value
