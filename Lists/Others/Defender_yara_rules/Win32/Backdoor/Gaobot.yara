rule Backdoor_Win32_Gaobot_B_2147584869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gaobot.gen!B"
        threat_id = "2147584869"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gaobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rec.php?&p=%i&v=%i" ascii //weight: 1
        $x_1_2 = "redirect.http" ascii //weight: 1
        $x_1_3 = "redirect.socks" ascii //weight: 1
        $x_1_4 = "redirect.stop" ascii //weight: 1
        $x_1_5 = "Autostart.net" ascii //weight: 1
        $x_1_6 = "Host: %s:%d" ascii //weight: 1
        $x_1_7 = "CRedirectBase" ascii //weight: 1
        $x_1_8 = "CRedirectHTTP_Thread" ascii //weight: 1
        $x_1_9 = "CRedirectSOCKS_Thread" ascii //weight: 1
        $x_1_10 = "Server: httpproxy" ascii //weight: 1
        $x_1_11 = "Proxy-Connection: close" ascii //weight: 1
        $x_1_12 = "Connection to %s:%d failed!" ascii //weight: 1
        $x_1_13 = "HTTP/1.0 200 Connection established" ascii //weight: 1
        $x_1_14 = "pxbg1" ascii //weight: 1
        $x_1_15 = "bla bla bla" ascii //weight: 1
        $x_1_16 = "g_pCommands" ascii //weight: 1
        $x_1_17 = "g_pInstaller" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Backdoor_Win32_Gaobot_C_2147584871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gaobot.gen!C"
        threat_id = "2147584871"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gaobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\keylog.txt" ascii //weight: 1
        $x_1_2 = "fucking error" ascii //weight: 1
        $x_1_3 = "Found Tiberian Sun CDKey (%s)." ascii //weight: 1
        $x_1_4 = "JOIN %s %s" ascii //weight: 1
        $x_1_5 = "PRIVMSG %s :" ascii //weight: 1
        $x_1_6 = "invalid nick!" ascii //weight: 1
        $x_1_7 = "Keylogger logging to %s" ascii //weight: 1
        $x_1_8 = "[nt-scan] not currently scanning" ascii //weight: 1
        $x_1_9 = "userpassword" ascii //weight: 1
        $x_1_10 = "UGLY BOT 1.0 by eric and vice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

