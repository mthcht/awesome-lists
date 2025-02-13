rule Backdoor_Win32_Sdbot_2147792325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot"
        threat_id = "2147792325"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii //weight: 1
        $x_2_2 = "IcmpSendEcho" ascii //weight: 2
        $x_2_3 = "Portfuck completed" ascii //weight: 2
        $x_2_4 = "SYN flood" ascii //weight: 2
        $x_2_5 = "sdbot v" ascii //weight: 2
        $x_2_6 = "sdbot 0.5b" ascii //weight: 2
        $x_2_7 = "sdbot.n" ascii //weight: 2
        $x_2_8 = "bot started." ascii //weight: 2
        $x_1_9 = "%s\\r.bat" ascii //weight: 1
        $x_2_10 = "spy created on" ascii //weight: 2
        $x_1_11 = "clone created on %s:%d, in channel %s." ascii //weight: 1
        $x_1_12 = "connection type: %s (%s). local IP address: %d.%d.%d.%d. connected from: %s" ascii //weight: 1
        $n_10_13 = "McAfee Stinger" ascii //weight: -10
        $n_10_14 = "McAfee Inc. Stinger" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sdbot_E_2147792337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot.gen!E"
        threat_id = "2147792337"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[SI] [SN]:%s [CN]:%s [UN]:%s [OS:]%s [CPU]" ascii //weight: 1
        $x_1_2 = "[UD] :) -> UD" ascii //weight: 1
        $x_1_3 = "[RS] :) -> %s:%d" ascii //weight: 1
        $x_1_4 = "[SRV]:%s [eXe]:%s [DLL]:%s [Location]:%s" ascii //weight: 1
        $x_1_5 = "DDoS" ascii //weight: 1
        $x_1_6 = "done with flood" ascii //weight: 1
        $x_1_7 = "%s:%d (Length:%d Threads:%d)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Sdbot_G_2147792343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot.gen!G"
        threat_id = "2147792343"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 00 33 d2 b9 3c 00 00 00 f7 f1 89 85 [0-64] 83 c1 02 89 8d [0-16] 33 d2 b9 a0 05 00 00 f7 f1}  //weight: 5, accuracy: Low
        $x_2_2 = {33 d2 b9 25 00 00 00 f7 f1 89 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 00 6a 05 68 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 83 f8 05 74}  //weight: 2, accuracy: Low
        $x_3_4 = {85 13 3c 9e a2 00}  //weight: 3, accuracy: High
        $x_1_5 = {30 30 37 00 30 77 6e 33 64 [0-4] 30 77 6e 65 64}  //weight: 1, accuracy: Low
        $x_1_6 = "%s\\Admin$\\" ascii //weight: 1
        $x_1_7 = "Mydoom " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sdbot_B_2147792346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot.gen!B"
        threat_id = "2147792346"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "fmap.svchctrl" ascii //weight: 5
        $x_5_2 = "evnt.svchctrl" ascii //weight: 5
        $x_5_3 = "mtx.svchctrl" ascii //weight: 5
        $x_5_4 = "mtx.svchost" ascii //weight: 5
        $x_5_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\ShellBot" ascii //weight: 5
        $x_5_6 = "trying to network read...1..." ascii //weight: 5
        $x_5_7 = "network_connectto... host : " ascii //weight: 5
        $x_5_8 = {5c 53 79 73 74 65 6d 5c [0-16] 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_5_9 = "M_POST.END." ascii //weight: 5
        $x_5_10 = "get_cont_length : " ascii //weight: 5
        $x_5_11 = "CONNECT " ascii //weight: 5
        $x_1_12 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_13 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_14 = "CreateEventA" ascii //weight: 1
        $x_1_15 = "CreateMutexA" ascii //weight: 1
        $x_1_16 = "InternetOpenA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_5_*) and 5 of ($x_1_*))) or
            ((11 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sdbot_C_2147792347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot.gen!C"
        threat_id = "2147792347"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kikgahjcewf" ascii //weight: 10
        $x_10_2 = "WINDOWS\\SYSTEM32\\mskikcom.exe" ascii //weight: 10
        $x_10_3 = "KIKBot.exe" ascii //weight: 10
        $x_10_4 = "USER kikbot kikbot kikbot :kikbot" ascii //weight: 10
        $x_1_5 = "lololkik" ascii //weight: 1
        $x_5_6 = "#kik" ascii //weight: 5
        $x_1_7 = "NICK %s" ascii //weight: 1
        $x_1_8 = "JOIN %s %s" ascii //weight: 1
        $x_1_9 = "PRIVMSG %s :%s" ascii //weight: 1
        $x_1_10 = "Downloading %s to %s..." ascii //weight: 1
        $x_1_11 = "Keylog ON." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sdbot_D_2147792348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot.gen!D"
        threat_id = "2147792348"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Tbbtyrobg/2.1 (+uggc://jjj.tbbtyrobg.pbz/obg.ugzy)" ascii //weight: 10
        $x_10_2 = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)" ascii //weight: 10
        $x_10_3 = ": Exploiting.. " ascii //weight: 10
        $x_10_4 = ": Exploited share %s\\C$\\WINDOWS\\system32\\" ascii //weight: 10
        $x_10_5 = "%s\\c$\\windows\\system32\\winsdf.exe" ascii //weight: 10
        $x_10_6 = "WINDOWS\\SYSTEM32\\srvdll32.exe" ascii //weight: 10
        $x_5_7 = "Trying to install spyware to generate cash..." ascii //weight: 5
        $x_5_8 = "Done with SYN flood [" ascii //weight: 5
        $x_1_9 = "PRIVMSG #rwnt :" ascii //weight: 1
        $x_1_10 = "NICK %s" ascii //weight: 1
        $x_1_11 = "USER %s 0 0 :%s" ascii //weight: 1
        $x_1_12 = "MODE %s +i" ascii //weight: 1
        $x_1_13 = "USERHOST %s" ascii //weight: 1
        $x_1_14 = "Sending .%d. pings to %s (.Packet size.): %d (.Timeout.): %d[ms]" ascii //weight: 1
        $x_1_15 = ": %s [%s] (.Local IP address.): %d.%d.%d.%d (.Connected from.): %s" ascii //weight: 1
        $x_1_16 = ": %I64uMHz " ascii //weight: 1
        $x_1_17 = ": %dKB total, %dKB free " ascii //weight: 1
        $x_1_18 = ": Windows %s [%d.%d, build %d] " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((6 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sdbot_AB_2147792357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sdbot.AB"
        threat_id = "2147792357"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8d ?? d8 fd ff ff ?? 6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 60 e0 40 00 50 ff 15 14 e0 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 01 00 00 00 85 c0 0f 84 ?? ?? 00 00 8d 4d f0 51 8d 95 94 fc ff ff 52 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ec f9 40 00 6a 00 ff 15 40 e0 40 00}  //weight: 1, accuracy: Low
        $x_100_3 = {25 64 00 00 32 36 30 30 00 00 00 00 44 4c 4c 00 44 4c 4c 00 53 79 73 74 65 6d 73 00 2a 00 00 00 25 64 00 00 32 36 30 30}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

