rule Backdoor_Win32_IRCbot_FH_2147790373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FH"
        threat_id = "2147790373"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb ee fe 45 ?? 80 7d ?? 5b 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 8d 44 24 04 50 6a 5a 68 00 04 00 00 e8 ?? ?? ?? ?? 83 f8 03}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c3 04 4e 75 d7 8b 23 00 6a 00 6a 01 6a 02}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 54 1a ff 80 f2 bc 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: High
        $x_1_5 = {50 72 6f 66 69 6c 65 30 00 00 00 00 ff ff ff ff 0d 00 00 00 5c 73 69 67 6e 6f 6e 73 33 2e 74 78}  //weight: 1, accuracy: High
        $x_1_6 = "shell=verb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_IRCbot_M_2147790381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!M"
        threat_id = "2147790381"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 05 8b f0 59 8d 7d f8 33 c0 f3 a6 75 07 1f 00 c6 45 ?? c8 88 5d ?? c6 45 ?? 04 88 5d ?? c6 45 ?? 60 ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f8 c8 88 5d f9 c6 45 fa 04 88 5d fb c6 45 fc 60 ff 15 ?? ?? ?? ?? 50 ff 15 [0-10] 6a 05}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 05 8d 85 ?? ?? ff ff 50 ff b5 ?? ?? ff ff e8 40 00 c6 85 ?? ?? ff ff c8 80 a5 ?? ?? ff ff 00 c6 85 ?? ?? ff ff 04 80 a5 ?? ?? ff ff 00 c6 85 ?? ?? ff ff 60}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 05 8d 85 ?? ?? ff ff 50 8b 8d ?? ?? ff ff 51 e8 40 00 c6 85 ?? ?? ff ff c8 c6 85 ?? ?? ff ff 00 c6 85 ?? ?? ff ff 04 c6 85 ?? ?? ff ff 00 c6 85 ?? ?? ff ff 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_IRCbot_DL_2147792023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.DL"
        threat_id = "2147792023"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 53 74 61 74 75 73 7c 55 70 64 61 74 65 20 46 61 69 6c 65 64}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 74 55 44 50 7c}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 74 53 59 4e}  //weight: 1, accuracy: High
        $x_1_4 = {00 49 44 4c 45 7c}  //weight: 1, accuracy: High
        $x_1_5 = {00 57 65 62 44 4c}  //weight: 1, accuracy: High
        $x_1_6 = {00 53 53 59 4e}  //weight: 1, accuracy: High
        $x_1_7 = {00 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c 4f 4c}  //weight: 1, accuracy: High
        $x_1_8 = {00 45 6e 46 69 72 65 7c}  //weight: 1, accuracy: High
        $x_1_9 = {00 55 53 42 7c 49 6e 66 65 63 74 65 64 20 44 72 69 76 65}  //weight: 1, accuracy: High
        $x_1_10 = {00 53 41 44 44 4e 45 57 7c 53 68 61 72 69 6e 67 2e 2e 2e 7c}  //weight: 1, accuracy: High
        $x_1_11 = {00 64 64 6f 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 53 54 4f 50 53 48 41 52 45 44 7c}  //weight: 1, accuracy: High
        $x_1_13 = {00 55 44 50 53 74 61 72 74 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_EW_2147792025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.EW"
        threat_id = "2147792025"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 3b 45 08 7d 21 e8 ?? ?? ?? 00 99 6a 0a 59 f7 f9 52 ff 75 fc}  //weight: 1, accuracy: Low
        $x_1_2 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_FU_2147792026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FU"
        threat_id = "2147792026"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 f2 bc 88 54 18 ff 43 4e 75 ?? 8b c7 8b 55 fc e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 3, accuracy: Low
        $x_1_2 = {84 c0 74 08 6a 02 53 e8 ?? ?? ?? ?? 8d 95 ?? fe ff ff 33 c0 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 00 6f 70 65 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 70 65 72 73 79 6e 55 8b ec 53 6a 3c 8b 0d}  //weight: 1, accuracy: High
        $x_1_5 = "ADDNEW|" ascii //weight: 1
        $x_1_6 = {49 44 4c 45 7c 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 74 61 72 74 55 44 50 7c 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 44 50 53 74 61 72 74 7c 00}  //weight: 1, accuracy: High
        $x_1_9 = {5b 7b 23 7d 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_GQ_2147792027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.GQ"
        threat_id = "2147792027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Starting IRC Thread" ascii //weight: 5
        $x_5_2 = "Injected formgrabber" ascii //weight: 5
        $x_1_3 = "dumbass.boatnet.ru" ascii //weight: 1
        $x_1_4 = ".paypal" wide //weight: 1
        $x_1_5 = "login_password=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_FZ_2147792028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FZ"
        threat_id = "2147792028"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 49 43 4b 20 00 00 00 55 53 45 52 20 00}  //weight: 1, accuracy: High
        $x_1_2 = "(compatible; Googlebot/" ascii //weight: 1
        $x_1_3 = ":SLOWLORIS Flood Activated!" ascii //weight: 1
        $x_1_4 = {ff d3 33 d2 b9 34 00 00 00 f7 f1 8b c6 83 e0 07 46 3b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_IRCbot_AF_2147792114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.AF"
        threat_id = "2147792114"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(W32.IRC.Bot.Malingsia.A.1) Sebagai pembalasan untuk IRC Bot Malay... rasakan kekuatan IRC Bot Worm" wide //weight: 1
        $x_1_2 = "... rasakan kekuatan IRC Bot Worm sebenarnya... hidup Vx3r Indonesia" wide //weight: 1
        $x_1_3 = "W32_IRC_Bot_Malingsia_A_1" ascii //weight: 1
        $x_1_4 = "Microsoft Office 2003" ascii //weight: 1
        $x_1_5 = "\"Windows Firewall/Internet Connection Sharing (ICS)\"" wide //weight: 1
        $x_1_6 = "\"Automatic Updates\"" wide //weight: 1
        $x_1_7 = "\"Security Center\"" wide //weight: 1
        $x_1_8 = "MALINGSIA" wide //weight: 1
        $x_1_9 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_10 = "ShellExecuteA" ascii //weight: 1
        $x_1_11 = "scripting.filesystemobject" wide //weight: 1
        $x_1_12 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_13 = "MethCallEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_A_2147792326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!A"
        threat_id = "2147792326"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "root" ascii //weight: 1
        $x_1_2 = "!@#$" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "%s\\c$\\winnt\\system" ascii //weight: 1
        $x_1_5 = "%s\\c$\\windows\\system" ascii //weight: 1
        $x_1_6 = "%s\\Admin$\\system" ascii //weight: 1
        $x_1_7 = "%s\\ipc$" ascii //weight: 1
        $x_1_8 = "PRIVMSG " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_IRCbot_OE_2147792330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.OE"
        threat_id = "2147792330"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32\\gmvvmokqi.exe" ascii //weight: 1
        $x_1_2 = "Message was sended!" ascii //weight: 1
        $x_1_3 = "Atack allready started..." ascii //weight: 1
        $x_1_4 = "ICMP flood started..." ascii //weight: 1
        $x_1_5 = "SYN flood started..." ascii //weight: 1
        $x_1_6 = "Flood is not active..." ascii //weight: 1
        $x_1_7 = "Atack terminated..." ascii //weight: 1
        $x_1_8 = "Downloading file.." ascii //weight: 1
        $x_1_9 = "Updating plugins..." ascii //weight: 1
        $x_1_10 = "Deleting plugin..." ascii //weight: 1
        $x_1_11 = "xchan" ascii //weight: 1
        $x_1_12 = "xport" ascii //weight: 1
        $x_1_13 = "xhost" ascii //weight: 1
        $x_1_14 = "Reconnecting to IRC server..." ascii //weight: 1
        $x_1_15 = "Now freq is %s" ascii //weight: 1
        $x_1_16 = "Now packetsize is %s" ascii //weight: 1
        $x_1_17 = "Key for GID %s updated" ascii //weight: 1
        $x_1_18 = "!!! SELFDESTRUCTION !!!" ascii //weight: 1
        $x_1_19 = "delplugin" ascii //weight: 1
        $x_1_20 = "updateplugins" ascii //weight: 1
        $x_1_21 = "Botnet Loader/1.00" ascii //weight: 1
        $x_1_22 = "csrss.exe" ascii //weight: 1
        $x_1_23 = "JOIN %s" ascii //weight: 1
        $x_1_24 = "NICK %s" ascii //weight: 1
        $x_1_25 = "USER %s %s %s :%s" ascii //weight: 1
        $x_1_26 = "SUiCiDE" ascii //weight: 1
        $x_1_27 = "fuck.all" ascii //weight: 1
        $x_1_28 = "SUiCiDE DDoS Endine" ascii //weight: 1
        $x_1_29 = "PRIVMSG %s :Welcome! Admin id: %s; GID: %d;" ascii //weight: 1
        $x_1_30 = "PRIVMSG %s :Failed to add new admin" ascii //weight: 1
        $x_1_31 = "PRIVMSG %s :Go avay, lam0 =)" ascii //weight: 1
        $x_1_32 = "USERHOST %s" ascii //weight: 1
        $x_1_33 = "PONG %s" ascii //weight: 1
        $x_1_34 = "http://%s/%s?act=getplugins" ascii //weight: 1
        $x_1_35 = "SUiCiDE/1.5" ascii //weight: 1
        $x_1_36 = "http://%s/%s?nick=%s&info=%s" ascii //weight: 1
        $x_1_37 = "suicide.exe" ascii //weight: 1
        $x_1_38 = "svcroot.exe" ascii //weight: 1
        $x_1_39 = "suicide.sys" ascii //weight: 1
        $x_1_40 = "svcroot" ascii //weight: 1
        $x_1_41 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_42 = "PeekNamedPipe" ascii //weight: 1
        $x_1_43 = "WriteFile" ascii //weight: 1
        $x_1_44 = "CreateThread" ascii //weight: 1
        $x_4_45 = {8b ec 50 52 51 ba 82 27 00 00 b8 50 bf 14 13 89 45 fc 81 45 fc cc 52 ff ff 8b 4d fc 8b 01 35 d7 d7 d7 d7 89 01 83 45 fc 04 4a 75 ed 59 5a 58}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((30 of ($x_1_*))) or
            ((1 of ($x_4_*) and 26 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_C_2147792334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!C"
        threat_id = "2147792334"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NYS Error: %d" ascii //weight: 1
        $x_1_2 = "NYS Fl00d" ascii //weight: 1
        $x_1_3 = "net share C$ /delete /y" ascii //weight: 1
        $x_1_4 = "gnip (%s)" ascii //weight: 1
        $x_1_5 = "rcpt to: <%s>" ascii //weight: 1
        $x_1_6 = "NICK: %s" ascii //weight: 1
        $x_1_7 = "(NTS tats):" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_IRCbot_D_2147792335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!D"
        threat_id = "2147792335"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spreading with start address [%s]" ascii //weight: 1
        $x_1_2 = "Spread routine stopped" ascii //weight: 1
        $x_1_3 = ".kl <application|security|system>" ascii //weight: 1
        $x_1_4 = ".login <hash>" ascii //weight: 1
        $x_1_5 = ".update <unix|win32> <url>" ascii //weight: 1
        $x_1_6 = "Attempting remote execution..." ascii //weight: 1
        $x_1_7 = "supass" ascii //weight: 1
        $x_1_8 = ":Restarting bot." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_E_2147792336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!E"
        threat_id = "2147792336"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTTP Flooder: couldnot" ascii //weight: 1
        $x_1_2 = "ICMP Flooder error:" ascii //weight: 1
        $x_1_3 = "UDP Flood terminated" ascii //weight: 1
        $x_1_4 = "Unable to kill process with PID %d" ascii //weight: 1
        $x_1_5 = "u_thread rewrited to %d" ascii //weight: 1
        $x_1_6 = "You are already loggined as admin" ascii //weight: 1
        $x_1_7 = "DCC Shell connection established with %s..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_CC_2147792339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.CC"
        threat_id = "2147792339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "\\photo album.zip" ascii //weight: 15
        $x_15_2 = "photo album2007.pif" ascii //weight: 15
        $x_10_3 = "PRIVMSG %s :MSN worm sent to: %d contacts" ascii //weight: 10
        $x_5_4 = "PRIVMSG %s : wow: %s %s:%s" ascii //weight: 5
        $x_5_5 = "PRIVMSG %s :Executed [%s]" ascii //weight: 5
        $x_5_6 = "PRIVMSG %s :Failed [%s]" ascii //weight: 5
        $x_5_7 = "NICK [%s][%iH]%s" ascii //weight: 5
        $x_5_8 = "net stop \"Security Center\"" ascii //weight: 5
        $x_5_9 = "net stop SharedAccess" ascii //weight: 5
        $x_1_10 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess" ascii //weight: 1
        $x_1_11 = "SYSTEM\\CurrentControlSet\\Services\\wuauserv" ascii //weight: 1
        $x_1_12 = "SYSTEM\\CurrentControlSet\\Services\\wscsvc" ascii //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 1
        $x_1_14 = "Lmfao hey im sending my new photo album, Some bare funny pictures!" ascii //weight: 1
        $x_1_15 = "lol my sister wants me to send you this photo album" ascii //weight: 1
        $x_1_16 = "Hey i been doing photo album! Should see em loL! accept please mate :)" ascii //weight: 1
        $x_1_17 = "HEY lol i've done a new photo album !:) Second ill find file and send you it." ascii //weight: 1
        $x_1_18 = "Hey wanna see my new photo album?" ascii //weight: 1
        $x_1_19 = "OMG just accept please its only my photo album!!" ascii //weight: 1
        $x_1_20 = "Hey accept my photo album, Nice new pics of me and my friends and stuff and when i was young lol..." ascii //weight: 1
        $x_1_21 = "Hey just finished new photo album! :) might be a few nudes ;) lol..." ascii //weight: 1
        $x_1_22 = "hey you got a photo album? anyways heres my new photo album :) accept k?" ascii //weight: 1
        $x_1_23 = "hey man accept my new photo album.. :( made it for yah, been doing picture story of my life lol.." ascii //weight: 1
        $x_1_24 = "lol lol lol :shadowbot2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_15_*) and 3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_15_*) and 4 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_15_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_15_*) and 6 of ($x_5_*))) or
            ((2 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_OP_2147792341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.OP"
        threat_id = "2147792341"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d8 85 db 7e 29 bf 01 00 00 00 8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8}  //weight: 1, accuracy: High
        $x_1_2 = {4d 44 41 54 41 31 00 00 4d 44 41 54 41 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_OY_2147792342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.OY"
        threat_id = "2147792342"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc b9 39 00 00 00 f3 a4 8b 45 f4 89 04 24 e8}  //weight: 1, accuracy: High
        $x_1_2 = "%q%b%b.cvc" ascii //weight: 1
        $x_1_3 = "Tcpqgml:" ascii //weight: 1
        $x_1_4 = {0d 0a 4e 50 47 54 4b 51 45 20 25 71}  //weight: 1, accuracy: High
        $x_1_5 = "SQCP %q \"" ascii //weight: 1
        $x_1_6 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 00 00 00 00 30 31 32 33 34}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 5b 25 73 5d 00 5f 00 00 00 00 53 51 43 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_R_2147792344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!R"
        threat_id = "2147792344"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRIVMSG %s :%lu%lu%lu%lu" ascii //weight: 1
        $x_1_2 = "%s :Cftp set to: %s:%d" ascii //weight: 1
        $x_1_3 = "PRIVMSG %s :MSN lol started" ascii //weight: 1
        $x_1_4 = "PRIVMSG %s :Keyboard capture" ascii //weight: 1
        $x_1_5 = "VNC%d.%d %s: %s - [AuthBypass]" ascii //weight: 1
        $x_1_6 = "&echo get %s >> " ascii //weight: 1
        $x_1_7 = "shell\\open\\command=" ascii //weight: 1
        $x_1_8 = {5b 70 53 74 6f 72 65 5d 00}  //weight: 1, accuracy: High
        $x_1_9 = ":Ftpserver set to: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_IRCbot_CV_2147792345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.CV"
        threat_id = "2147792345"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "modSocketMaster" ascii //weight: 1
        $x_1_2 = "modURLSource" ascii //weight: 1
        $x_1_3 = {6d 73 6e 70 77 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {6b 61 79 6e 61 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 78 74 4c 45 45 43 48 00}  //weight: 1, accuracy: High
        $x_1_6 = {54 78 74 50 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {52 00 4f 00 4b 00 55 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {52 00 4b 00 49 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "PRIVMSG Root :" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_B_2147792352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!B"
        threat_id = "2147792352"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dirx9.exe" ascii //weight: 5
        $x_5_2 = "Winjava xml" ascii //weight: 5
        $x_5_3 = "JOIN" ascii //weight: 5
        $x_5_4 = "NICK" ascii //weight: 5
        $x_5_5 = "PRIVMSG" ascii //weight: 5
        $x_1_6 = "threads" ascii //weight: 1
        $x_1_7 = "killthread" ascii //weight: 1
        $x_1_8 = "execute" ascii //weight: 1
        $x_1_9 = "listprocesses" ascii //weight: 1
        $x_1_10 = "killprocess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_OU_2147792353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.OU!dll"
        threat_id = "2147792353"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "john.free4people.net" ascii //weight: 10
        $x_10_2 = {4a 4f 49 4e 00}  //weight: 10, accuracy: High
        $x_10_3 = {4e 49 43 4b 00}  //weight: 10, accuracy: High
        $x_10_4 = {50 52 49 56 4d 53 47 00}  //weight: 10, accuracy: High
        $x_10_5 = "%s new[%s][%iH]%s" ascii //weight: 10
        $x_7_6 = "fuckoff" ascii //weight: 7
        $x_1_7 = "Hey please look at me and my pet ..  :p" ascii //weight: 1
        $x_1_8 = "Looking for hot summer pictures  ? well here they are !! (h)" ascii //weight: 1
        $x_1_9 = "Look at me and my volleyball team, working our asses offff (h)" ascii //weight: 1
        $x_1_10 = "Hey please look at me and my pet .. :p" ascii //weight: 1
        $x_1_11 = "Psssssst .... just between me and you, please accept :$" ascii //weight: 1
        $x_1_12 = "This is me totaly naked :o please dont send to anyone else" ascii //weight: 1
        $x_1_13 = "bak sana  Paris Hilton ne hale gelmis hapiste :(" ascii //weight: 1
        $x_1_14 = "Sen ve Ben !!! .... BAK :p" ascii //weight: 1
        $x_1_15 = "Baksana benim fotograflara hihi :p" ascii //weight: 1
        $x_1_16 = "Hey benim fotolarimi kabul et :o !!" ascii //weight: 1
        $x_1_17 = "Iyi arkadasimla fotorafdayim :$ !!" ascii //weight: 1
        $x_1_18 = "benim bu ciplak fotoda :o ama baskasina yollama" ascii //weight: 1
        $x_1_19 = "Regarde les tof de mes vacances en tunisie loool" ascii //weight: 1
        $x_1_20 = "Toi et moi !!! .... regarde :p" ascii //weight: 1
        $x_1_21 = "hey stp regarde mes tof !" ascii //weight: 1
        $x_1_22 = "Hey s'il te plait accepte mes photos :o !!" ascii //weight: 1
        $x_1_23 = "Une tof de moi et ...:$ !!" ascii //weight: 1
        $x_1_24 = "Kijk hoe erg Paris Hilton er aan toe is na gevangenschap :(" ascii //weight: 1
        $x_1_25 = "Jij en Ik !!!! .... kijk :p" ascii //weight: 1
        $x_1_26 = "Kijk eens naar mijn fotos hihi :p" ascii //weight: 1
        $x_1_27 = "HEY !! accepteer mn fotos dan !" ascii //weight: 1
        $x_1_28 = "met mijn beste vriend op de foto !! :$" ascii //weight: 1
        $x_1_29 = "Dit ben ik naakt op de foto, stuur alsjeblieft niet door." ascii //weight: 1
        $x_1_30 = "guck wie scheisse Paris Hilton aussieht, seitdem sie wieder aus dem knast ist :(" ascii //weight: 1
        $x_1_31 = "du und ich !!! ....guck :p" ascii //weight: 1
        $x_1_32 = "siehe meine fotos hihi :p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_7_*) and 20 of ($x_1_*))) or
            ((4 of ($x_10_*) and 17 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_7_*) and 10 of ($x_1_*))) or
            ((5 of ($x_10_*) and 7 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_PR_2147792358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.PR"
        threat_id = "2147792358"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\PyTh0n\\Desktop\\PyTh0n Bot\\Project1.vbp" wide //weight: 1
        $x_1_2 = "SocketIRC_DataArrival" ascii //weight: 1
        $x_1_3 = "irc.cyberarmy.net" wide //weight: 1
        $x_1_4 = "%SocketIRC" ascii //weight: 1
        $x_1_5 = "RemotePort" ascii //weight: 1
        $x_1_6 = "RemoteHost" ascii //weight: 1
        $x_1_7 = "StartBot" ascii //weight: 1
        $x_1_8 = "DoS_Connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_CL_2147792359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.CL"
        threat_id = "2147792359"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NICK %s%c" ascii //weight: 1
        $x_1_2 = "BuZBoT" ascii //weight: 1
        $x_1_3 = "jGjSjMjVjIjRjP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_QA_2147792360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.QA"
        threat_id = "2147792360"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "eu.undernet.org" ascii //weight: 10
        $x_10_2 = "NICK bla" ascii //weight: 10
        $x_10_3 = "Small IRC Bot" ascii //weight: 10
        $x_5_4 = "Client hook" ascii //weight: 5
        $x_1_5 = "join %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_HI_2147792361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.HI"
        threat_id = "2147792361"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 6c 6f 77 70 6f 73 74 00 73 6c 6f 77 6c 6f 72 69 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "flood.anope" ascii //weight: 1
        $x_1_3 = "%s\\I%li.bat" ascii //weight: 1
        $x_1_4 = "ajax IRC Client" ascii //weight: 1
        $x_1_5 = "/MOTD command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_G_2147792362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!G"
        threat_id = "2147792362"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trueman2" wide //weight: 1
        $x_1_2 = "Downloading bot update from" wide //weight: 1
        $x_1_3 = "Bot IRC Commands" wide //weight: 1
        $x_20_4 = "Miguel Source Code\\TRUEMAN" wide //weight: 20
        $x_1_5 = "GET /linux/ubuntu-releases" wide //weight: 1
        $x_1_6 = "Speedtestsock" ascii //weight: 1
        $x_1_7 = "Primary Bot :" ascii //weight: 1
        $x_1_8 = "Speed test :" ascii //weight: 1
        $x_1_9 = "\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" wide //weight: 1
        $x_1_10 = "\\LINK.EXE.M" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_I_2147792363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!I"
        threat_id = "2147792363"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Botkiller thread started." ascii //weight: 1
        $x_1_2 = "Bot killed and removed: %s (pid: %d)!" ascii //weight: 1
        $x_1_3 = "Guard\" &net stop \"Security Center\" &net stop \"Symantec" ascii //weight: 1
        $x_1_4 = "VNC%d.%d %s: %s - [NoPassword]" ascii //weight: 1
        $x_1_5 = "Patching tcpip.sys." ascii //weight: 1
        $x_1_6 = "TCPIP.SYS fixed, version %d." ascii //weight: 1
        $x_1_7 = {25 73 20 25 73 20 22 66 6f 25 64 2e 6e 65 74 22 20 22 6c 6f 6c 22 20 3a 25 73 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 66 74 70 20 2d 6e 20 2d 76 20 2d 73 3a 69 6b 20 26 64 65 6c 20 69 6b 20 26 25 73 20 26 65 78 69 74 00 00 00 25 73 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_IRCbot_AN_2147792370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.AN"
        threat_id = "2147792370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1401"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1000
        $x_100_2 = "c:\\windows\\system32\\ircaddon.exe" ascii //weight: 100
        $x_100_3 = "-lamerz" ascii //weight: 100
        $x_100_4 = "startbotoi" ascii //weight: 100
        $x_40_5 = "stopbotoi" ascii //weight: 40
        $x_40_6 = "socket buzzor" ascii //weight: 40
        $x_40_7 = "Honey Gonnecting" ascii //weight: 40
        $x_10_8 = "enternot" ascii //weight: 10
        $x_10_9 = "NICK %s" ascii //weight: 10
        $x_10_10 = "JOIN %s %s" ascii //weight: 10
        $x_10_11 = "PONG %s" ascii //weight: 10
        $x_10_12 = "USER %s \"nick\" \"%s\" :%s" ascii //weight: 10
        $x_10_13 = "[Num Lock]" ascii //weight: 10
        $x_10_14 = "[Down]" ascii //weight: 10
        $x_10_15 = "[Right]" ascii //weight: 10
        $x_10_16 = "[Left]" ascii //weight: 10
        $x_1_17 = "ShellExecuteA" ascii //weight: 1
        $x_1_18 = "Microsoft Instant Messaging Protocol" ascii //weight: 1
        $x_1_19 = "Microsoft IIS 5.0" ascii //weight: 1
        $x_200_20 = "PRIVMSG %s :RPCNUKE" ascii //weight: 200
        $x_200_21 = "vulnerable samba" ascii //weight: 200
        $x_50_22 = {6e 65 74 20 73 68 61 72 65 20 2f 64 65 6c 65 74 65 20 ?? 24}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 3 of ($x_40_*) and 8 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 3 of ($x_40_*) and 9 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_40_*) and 7 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_40_*) and 8 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_40_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_40_*) and 4 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_40_*) and 6 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_40_*) and 7 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 2 of ($x_40_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 2 of ($x_40_*) and 3 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 3 of ($x_40_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_50_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_50_*) and 6 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 2 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_40_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 3 of ($x_40_*) and 8 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 3 of ($x_40_*) and 9 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_50_*) and 2 of ($x_40_*) and 7 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_50_*) and 2 of ($x_40_*) and 8 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_50_*) and 3 of ($x_40_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_50_*) and 3 of ($x_40_*) and 4 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_40_*) and 6 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_40_*) and 7 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 2 of ($x_40_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 2 of ($x_40_*) and 3 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 3 of ($x_40_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_50_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_50_*) and 6 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 2 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_40_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 2 of ($x_100_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 2 of ($x_100_*) and 1 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 2 of ($x_100_*) and 1 of ($x_40_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 2 of ($x_100_*) and 1 of ($x_50_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_200_*) and 3 of ($x_100_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_200_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_200_*) and 1 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_200_*) and 1 of ($x_40_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_200_*) and 1 of ($x_50_*))) or
            ((1 of ($x_1000_*) and 2 of ($x_200_*) and 1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_KX_2147792371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.KX"
        threat_id = "2147792371"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 6f 74 20 43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 [0-16] 20 6f 6e 20 70 6f 72 74 20 36 36 36}  //weight: 1, accuracy: Low
        $x_1_2 = "Shellcode used: (%ld" ascii //weight: 1
        $x_1_3 = "!ReverseShell" ascii //weight: 1
        $x_1_4 = "ircBot->nick" ascii //weight: 1
        $x_1_5 = "#bot-bot-bot" ascii //weight: 1
        $x_1_6 = "NICK BotBotBot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_IRCbot_GL_2147792372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.GL"
        threat_id = "2147792372"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irc.hackt.org" ascii //weight: 1
        $x_1_2 = "USER NayrA 0 * :NayrA" ascii //weight: 1
        $x_1_3 = "[%s|%s%c]%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_GM_2147792373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.GM"
        threat_id = "2147792373"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "0.0.0.0 www.microsoft.com" ascii //weight: 10
        $x_10_2 = "0.0.0.0 www.virustotal.com" ascii //weight: 10
        $x_1_3 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "blocked DNS: \"%s\"" ascii //weight: 1
        $x_1_5 = "{%s|x64|%s|%s}" ascii //weight: 1
        $x_1_6 = "irc.heckbig.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_QN_2147792374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.QN"
        threat_id = "2147792374"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 77 69 6e 61 70 69 2e 65 78 65 [0-15] 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-5] 2f 77 69 6e 61 70 69 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_1_2 = "\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_3 = "taskkill /F /IM vbc.exe" ascii //weight: 1
        $x_1_4 = "USER H4X0R-B0T \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_FI_2147792377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FI"
        threat_id = "2147792377"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "update.bqlab.com" ascii //weight: 1
        $x_1_2 = "vibot" ascii //weight: 1
        $x_1_3 = "flood on %s:%s for %s seconds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_FI_2147792377_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FI"
        threat_id = "2147792377"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "update.bqlab.com" ascii //weight: 2
        $x_2_2 = "vibot" ascii //weight: 2
        $x_1_3 = ":PyNet by viraL, revision: %s" ascii //weight: 1
        $x_1_4 = ":UpdateThread: %s" ascii //weight: 1
        $x_1_5 = ":SynThread: %s" ascii //weight: 1
        $x_1_6 = ":Install.Remove(): %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_SX_2147792378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.SX"
        threat_id = "2147792378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add HKLM\\software\\microsoft\\windows\\currentversion\\run /v run32 /d \"%windir%\\system32\\rundl32.exe\" /f" ascii //weight: 1
        $x_1_2 = "%windir%\\system\\winlogon.exe" ascii //weight: 1
        $x_1_3 = {5b 69 72 63 5d 0d 0a 6a 3d 6a 6f 69 6e 0d 0a 6e 3d 6e 69 63 6b 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_F_2147792380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!F"
        threat_id = "2147792380"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 60 6a 00 6a 00 6a 00 6a ff ff 15 ?? ?? ?? 00 85 c0 74 08 6a 00 ff 15 20 00 c6 85 ?? ?? ff ff c8 c6 85 ?? ?? ff ff 00 c6 85 ?? ?? ff ff 04 c6 85 ?? ?? ff ff 00 c6 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_H_2147792381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!H"
        threat_id = "2147792381"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 a0 05 00 00 40 40 f7 f1 66 83 65 ?? 00 33 c0 b9 ff 01 00 00 f3 ab 66 ab 69 d2 60 ea 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_J_2147792387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!J"
        threat_id = "2147792387"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 64 03 40 30 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 0a 00 00 43 3a 5c 55 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_K_2147792388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!K"
        threat_id = "2147792388"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 05 e8 f9 ff ff ff 5b 31 c9 66 b9 ff ff 80 73 0e ff 43 e2 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_N_2147792389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!N"
        threat_id = "2147792389"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 ed 00 00 00 ff 36 68 09 12 d6 63 e8 f7 00 00 00 89 46 08 e8 a2 00 00 00 ff 76 04 68 6b d0 2b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_P_2147792391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!P"
        threat_id = "2147792391"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 55 0c 89 45 00 6a 00 68 00 02 00 00 56 53 ff 55 28 85 c0 74 11 78 1a ff 75 00 50 6a 01 56 ff 55 10 83 c4 10 eb df}  //weight: 3, accuracy: High
        $x_2_2 = {ac 84 c0 74 09 2c 44 34 08 04 11 aa eb f2 aa}  //weight: 2, accuracy: High
        $x_1_3 = {85 c0 74 57 66 c7 85 ?? ?? ?? ?? 2a 08 66 c7}  //weight: 1, accuracy: Low
        $x_1_4 = {19 02 00 00 74 05 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 75 08 33 c9 ac 32 c8 c1 c1 05 ac 84 c0 75 f6}  //weight: 1, accuracy: High
        $x_1_6 = "NvCplDaemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_S_2147792396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!S"
        threat_id = "2147792396"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" ascii //weight: 1
        $x_1_2 = "[.ShellClassInfo]" ascii //weight: 1
        $x_1_3 = "wormride.tftpd" ascii //weight: 1
        $x_1_4 = "JOIN %s" ascii //weight: 1
        $x_1_5 = "SMBr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_L_2147792401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!L"
        threat_id = "2147792401"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 03 57 8d 5e 1c 6a 01 68 00 00 00 80 53 ff 56 04 89 45 fc 8d 86 20 01 00 00 50 57 57 ff 56 08 89 45 08 ff 56 0c 3d b7 00 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_O_2147792402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!O"
        threat_id = "2147792402"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VNC Scanning Bot" ascii //weight: 1
        $x_1_2 = "RFB 003.008" ascii //weight: 1
        $x_1_3 = "[MAIN]" ascii //weight: 1
        $x_1_4 = "RXBot" ascii //weight: 1
        $x_1_5 = "[SCAN]" ascii //weight: 1
        $x_1_6 = "[FTP]" ascii //weight: 1
        $x_1_7 = "scan.stop" ascii //weight: 1
        $x_1_8 = "NZM/ST" ascii //weight: 1
        $x_1_9 = "scanall" ascii //weight: 1
        $x_1_10 = "YaBot" ascii //weight: 1
        $x_20_11 = {59 85 c0 59 74 ?? 68 d0 07 00 00 ?? ?? ?? ?? ?? ?? 81 ec 28 01 00 00 8d 75 ?? 6a 4a 59 8b fc ff 75 ?? f3 a5 e8 ?? ?? ?? ?? 81 c4 2c 01 00 00 8b 45 ?? 83 c0 08 89 45 ?? 39 18 75}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_CK_2147792405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.CK"
        threat_id = "2147792405"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData%\\schost.exe" ascii //weight: 1
        $x_1_2 = "cmd /c REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V SCVHOST" ascii //weight: 1
        $x_1_3 = {6e 64 65 74 65 63 74 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_T_2147792406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!T"
        threat_id = "2147792406"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 24 50 83 c0 0a 83 e0 fe 50 e8 ?? ?? ff ff 5a 66 c7 44 02 fe 00 00 83 c0 08 5a 89 50 fc c7 40 f8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 18 ff 8b cb 83 e1 7f 32 c1 8b 4d f8 8b 7d e0 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef 8b c3 83 e0 01 85 c0 75 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_BH_2147792409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.BH"
        threat_id = "2147792409"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {b9 f4 01 00 00 bb 41 41 41 41 2b 4d fc 8b c3 8d bd 3e fd ff ff 8d b5 60 f9 ff ff 8b d1 6a 02 c1 e9 02 f3 ab 8b ca ba 32 02 00 00}  //weight: 4, accuracy: High
        $x_5_2 = {ff d7 85 c0 75 47 83 7d fc 02 77 41 ff 15 ?? ?? ?? ?? 83 f8 05 74 0b ff 15 ?? ?? ?? ?? 83 f8 20 75 1a ff d6 2b 45 f8 3d a0 86 01 00 73 0b 68 e8 03 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = {7e 59 c7 45 08 ?? ?? 40 00 8b 4d 08 66 8b 46 14 66 39 01 75 18 57 68 ?? ?? 40 00 6a 02 57 66 89 47 10 89 5f 14 e8 ?? ?? 00 00 83 c4 10 83 45 08 28}  //weight: 5, accuracy: Low
        $x_1_4 = {50 52 49 56 4d 53 47 00 02 5b 02 03 31 32 25 73 03 02 5d 02 3a 20 45 78 70 6c 6f 69 74 65 64 3a 20 25 73}  //weight: 1, accuracy: High
        $x_1_5 = {53 52 56 53 56 43 00 00 2a 53 65 72 76 65 72 20 32 30 30 33 20 2a 00 00 2a 4c 41 4e 20 4d 61 6e 61 67 65 72 20 34 2e 30 2a}  //weight: 1, accuracy: High
        $x_1_6 = {45 78 70 6c 6f 69 74 20 53 74 61 74 69 73 74 69 63 73 3a 00 25 69 2e 25 69 2e 78 2e 78 00 00 00 78 2e 78 2e 78 2e 78 00 6e 6f 6e 65 00 00 00 00 02 5b 02 03 31 32 53 43 41 4e 03 02 5d}  //weight: 1, accuracy: High
        $x_1_7 = "MS08-067" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_V_2147792412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!V"
        threat_id = "2147792412"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 74 24 10 33 db 33 ed 3b f3 7e 58 81 fe 00 02 00 00 7d 50 69 f6 18 02 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {62 74 3e 8d 45 08 50 ff 15 ?? ?? ?? ?? 83 f8 02 75 2f}  //weight: 2, accuracy: Low
        $x_2_3 = {55 30 04 3e 43 e8 ?? ?? ?? ?? 3b d8 59 72 eb}  //weight: 2, accuracy: Low
        $x_2_4 = {7e 72 56 8d 45 ?? 6a 28 50 ff 75 ?? 89 75 ?? 89 5d ?? ff 75 ?? ff 15 ?? ?? ?? ?? ff 75 ?? ff 75 ?? 68 2d 10 00 00 ff 75 ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 45 08 53 33 db 56 80 38 3a 57 89 4d fc 89 5d f4 0f 85}  //weight: 2, accuracy: High
        $x_1_6 = "File download: %.1fKB to: %s @ %.1fKB/sec." ascii //weight: 1
        $x_1_7 = "Outbreak Private For " ascii //weight: 1
        $x_1_8 = "[autorun]" ascii //weight: 1
        $x_1_9 = "Infected drive: %s" ascii //weight: 1
        $x_1_10 = "Done with flood (%iKB/sec).05" ascii //weight: 1
        $x_1_11 = "ddosing %s:%s/%s secs." ascii //weight: 1
        $x_1_12 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_13 = "Download Command = %s [URL] [Location]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_U_2147792413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!U"
        threat_id = "2147792413"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 18 02 00 00 16 00 81 bd ?? ?? ff ff 00 02 00 00 (7d|0f 8d)}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 00 32 81 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 eb ce}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 62 74 ?? 8d 45 ?? 50 ff 15 ?? ?? ?? 3f 83 f8 02 75}  //weight: 2, accuracy: Low
        $x_1_4 = "File download: %.1fKB to: %s @ %.1fKB/sec." ascii //weight: 1
        $x_1_5 = "%s Flooding %s:%s for %s seconds" ascii //weight: 1
        $x_1_6 = "[autorun]" ascii //weight: 1
        $x_1_7 = "Infected drive: %s" ascii //weight: 1
        $x_1_8 = "Done with flood (%iKB/sec).05" ascii //weight: 1
        $x_1_9 = "%s Downloading URL: %s to: %s." ascii //weight: 1
        $x_1_10 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_11 = "Ping Timeout? (%d-%d)%d/%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_W_2147792415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!W"
        threat_id = "2147792415"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 3c 41 88 45 fc 74 25 3c 42 74 21 3c 61 74 1d 3c 62 74 19 8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 02 75 0a}  //weight: 1, accuracy: Low
        $x_1_3 = "%s %s \"\" \"lol\" :%s" ascii //weight: 1
        $x_1_4 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_5 = {53 48 45 4c 4c 33 32 2e 64 6c 6c 2c 34 0d 0a 61 63 74 69 6f 6e 3d 4f 70 65 6e 20 66 6f 6c 64 65 72 20 74 6f}  //weight: 1, accuracy: High
        $x_1_6 = "\\google_cache%s.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_IRCbot_FE_2147792416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FE"
        threat_id = "2147792416"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zyma Group" ascii //weight: 1
        $x_1_2 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73}  //weight: 1, accuracy: High
        $x_1_3 = "PRIVMSG %s :%s%s%s%s%s%i" ascii //weight: 1
        $x_1_4 = ":!udpflood" ascii //weight: 1
        $x_1_5 = ":!recon" ascii //weight: 1
        $x_1_6 = ":!update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_IRCbot_X_2147792417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!X"
        threat_id = "2147792417"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "TTKRJPJD6S8GJHGT68DDJSOMSDL" ascii //weight: 2
        $x_2_2 = ".::[Speedtest]::. %d kb/s" ascii //weight: 2
        $x_2_3 = "r3m0v3rl0" ascii //weight: 2
        $x_2_4 = "%s ERROR Exc! No Updated!" ascii //weight: 2
        $x_2_5 = "%s Dowload Failed!" ascii //weight: 2
        $x_1_6 = {31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 0a [0-4] 31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 6d 61 63 61 66 65 65 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_2_7 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15}  //weight: 2, accuracy: High
        $x_1_8 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d}  //weight: 1, accuracy: High
        $x_2_9 = {68 02 20 00 00 ff 15 ?? ?? ?? ?? 8b f0 56 ff 15 ?? ?? ?? ?? ff 74 24 08 50 e8 ?? ?? ?? ?? 59 59 56 ff 15 ?? ?? ?? ?? 56 6a 01 ff 15 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_10 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a (76|56) ff 15 ?? ?? ?? ?? 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_Q_2147792418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!Q"
        threat_id = "2147792418"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Slave.DLL" ascii //weight: 1
        $x_1_2 = "Reverse Socks5 Slave Bot" ascii //weight: 1
        $x_1_3 = "By WinEggDrop!" ascii //weight: 1
        $x_1_4 = "PRIVMSG %s :Set DNS IP List Thru Link List Successfully" ascii //weight: 1
        $x_1_5 = "PRIVMSG %s :Fail To Send Request For Setting File Pointer" ascii //weight: 1
        $x_1_6 = "PRIVMSG %s :%s Has Been Hidden Successfully" ascii //weight: 1
        $x_1_7 = "PRIVMSG %s :Modify IRC BOT Enable Successfully" ascii //weight: 1
        $x_1_8 = "PRIVMSG %s :IRC Channel Key Must Be Less Than 32 Characters" ascii //weight: 1
        $x_1_9 = "Remote Proxy Chain Is Taking Place" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_Q_2147792418_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!Q"
        threat_id = "2147792418"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRIVMSG %s :Add & Activate Global Remote Proxy Chain Successfully" ascii //weight: 1
        $x_1_2 = "Anti Hamming     : Unlimited" ascii //weight: 1
        $x_1_3 = "Fail To Un-Protect The Process & Fail To Save" ascii //weight: 1
        $x_1_4 = "Anti Scan Feature Has Been De-Activated But Fail To Save" ascii //weight: 1
        $x_1_5 = "PRIVMSG %s :Create IRC Bot Thread Successfully" ascii //weight: 1
        $x_1_6 = "IRC Bot Running But Offline" ascii //weight: 1
        $x_1_7 = "C:\\SocksProxy.DLL" ascii //weight: 1
        $x_1_8 = "Remote Admin Port Must Be Digits" ascii //weight: 1
        $x_1_9 = "Everything That Has A Beginning Has An End" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_AQ_2147792428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.AQ"
        threat_id = "2147792428"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%d.%d.%d.%d" ascii //weight: 10
        $x_10_2 = "PRIVMSG %s" ascii //weight: 10
        $x_10_3 = "JOIN %s %s" ascii //weight: 10
        $x_10_4 = "USERHOST %s" ascii //weight: 10
        $x_10_5 = "FtpOpenFileA" ascii //weight: 10
        $x_10_6 = "InternetReadFile" ascii //weight: 10
        $x_10_7 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_8 = "bot_update" ascii //weight: 1
        $x_1_9 = "thread_kill" ascii //weight: 1
        $x_1_10 = "file_delete" ascii //weight: 1
        $x_1_11 = "threads_list" ascii //weight: 1
        $x_1_12 = "process_kill" ascii //weight: 1
        $x_1_13 = "file_download" ascii //weight: 1
        $x_1_14 = "bot_reconnect" ascii //weight: 1
        $x_1_15 = "bot_raw_command" ascii //weight: 1
        $x_1_16 = "Killed all threads" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_BF_2147792430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.BF"
        threat_id = "2147792430"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/w32send.dll" ascii //weight: 10
        $x_10_2 = "/messpass.exe" ascii //weight: 10
        $x_10_3 = "POP3 Password" ascii //weight: 10
        $x_10_4 = "userinit.exe,sysem32.exe" ascii //weight: 10
        $x_1_5 = "geticq" ascii //weight: 1
        $x_1_6 = "PRIVMSG" ascii //weight: 1
        $x_1_7 = "xbashbot" ascii //weight: 1
        $x_1_8 = "k3yloger" ascii //weight: 1
        $x_1_9 = "xspecialdl" ascii //weight: 1
        $x_1_10 = "givepassto" ascii //weight: 1
        $x_1_11 = "d0wnloading" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_BG_2147792431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.BG"
        threat_id = "2147792431"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".fbi.gov" ascii //weight: 10
        $x_10_2 = "Start flooding" ascii //weight: 10
        $x_10_3 = "Internet Security Service" ascii //weight: 10
        $x_10_4 = "{28ABC5C0-4FCB-11CF-AAX5-81CX1C635612}" ascii //weight: 10
        $x_1_5 = "irc.h1t3m.org" ascii //weight: 1
        $x_1_6 = "ise32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_EV_2147792437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.EV"
        threat_id = "2147792437"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 08 88 00 00 00 c7 46 0c 84 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 04 8b 08 6a 00 ff d1 b8 01 00 00 00 c2 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 cb 01 c6 44 24 2a 50 c6 44 24 2b 49 c6 44 24 2c 4e c6 44 24 2d 47 c6 44 24 2e 00 ff d6 83 c4 08 85 c0 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_GS_2147792438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.GS"
        threat_id = "2147792438"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":DDOS Penggunaan: !ddos.start ip port" wide //weight: 1
        $x_1_2 = "modbukasitus" ascii //weight: 1
        $x_1_3 = "ddos.status" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_DR_2147792439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.DR"
        threat_id = "2147792439"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 83 3c 85 18 ?? ?? ?? ?? 0f 84 ?? 00 00 00 83 65 fc 00 eb ?? 8b 45 fc 40 89 45 fc 8b 45 f4 ff 34 85 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4d 08 03 4d f8 8b 55 fc 8a 04 10 32 01 8b 4d f4}  //weight: 2, accuracy: High
        $x_2_3 = {8b 4d fc 0f be 04 08 f7 d0 8b 4d f4 8b 0c 8d ?? ?? ?? ?? 8b 55 fc 88 04 11}  //weight: 2, accuracy: Low
        $x_1_4 = {49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_Y_2147792443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!Y"
        threat_id = "2147792443"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 41 53 53 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 53 45 52 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 52 49 56 4d 53 47 00}  //weight: 1, accuracy: High
        $x_1_4 = "shellexecute=" ascii //weight: 1
        $x_1_5 = "[autorun]" ascii //weight: 1
        $x_1_6 = "autorun.inf" ascii //weight: 1
        $x_1_7 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = "del \"%s\">nul" ascii //weight: 1
        $x_1_9 = "ping 0.0.0.0>nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_IRCbot_FP_2147792446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.FP"
        threat_id = "2147792446"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "5850505589E55753515231C0EB0" wide //weight: 3
        $x_3_2 = "botinfo.wb" wide //weight: 3
        $x_3_3 = "ssl32.cert" wide //weight: 3
        $x_1_4 = "wunderbot" wide //weight: 1
        $x_1_5 = "#runescape" wide //weight: 1
        $x_1_6 = "#powerbot" wide //weight: 1
        $x_1_7 = "#swiftkit" wide //weight: 1
        $x_1_8 = "#minecraft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCbot_AB_2147792447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!AB"
        threat_id = "2147792447"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s %s \"\" \"lol\" :%s" ascii //weight: 1
        $x_1_2 = {85 c0 59 76 15 8a 83 ?? ?? 40 00 55 30 04 3e 43 e8 ?? ?? 00 00 3b d8 59 72 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {59 39 45 f8 73 1b 8b 45 08 03 45 fc 8b 4d f8 8a 00 32 81 ?? ?? 40 00 8b 4d 08 03 4d fc 88 01 eb ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_IRCbot_AA_2147792452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.gen!AA"
        threat_id = "2147792452"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {75 21 6a 3f 8d 45 c0 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 ff 75 10 8d 45 c0 ff 75 10 50 68 ?? ?? 40 00 eb 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_SZ_2147792460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.SZ"
        threat_id = "2147792460"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 53 04 89 53 08 c1 ca 10 6b d2 0d c1 ca 10 6b d2 0d [0-3] 8a ?? 04 32 [0-3] 20 74 10 81 3e 47 45 54 20 74 ?? 83 63 04 00 83 63 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "65520:TCP:*:Enabled:FF 65520 TCP" ascii //weight: 1
        $x_1_3 = {4e 49 43 4b 20 61 62 63 64 65 66 67 68 0a 55 53 45 52 20 25 63 25 2e 36 78 20 2e 20 2e 20 3a 44 49 53 50 41 54 43 48 45 52 20 25 64}  //weight: 1, accuracy: High
        $x_1_4 = "MKTUN %s%.8X %u %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_AE_2147792472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot.AE"
        threat_id = "2147792472"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 3d ?? ?? ?? 00 8a 82 ?? ?? ?? 00 8a 14 ?? 32 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 30 00 00 8b ?? 50 8b ?? 34}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 48 34 51 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCbot_2147792477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCbot!MTB"
        threat_id = "2147792477"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PASS" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_3 = "Desktop.ini" ascii //weight: 1
        $x_1_4 = "autorun.inf" ascii //weight: 1
        $x_1_5 = "645FF040-5081-101B-9F08-00AA002F954E" ascii //weight: 1
        $x_1_6 = "UseAuTOPLAY=1" ascii //weight: 1
        $x_1_7 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_8 = "ping 0.0.0.0>nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

