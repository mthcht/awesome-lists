rule Worm_Win32_Spybot_2147555602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Spybot"
        threat_id = "2147555602"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Server: SpyBot" ascii //weight: 4
        $x_1_2 = "SOFTWARE\\KAZAA\\LocalContent" ascii //weight: 1
        $x_1_3 = "PRIVMSG" ascii //weight: 1
        $x_1_4 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_5 = "\\cmd.exe" ascii //weight: 1
        $x_1_6 = "Keylogger Started" ascii //weight: 1
        $x_2_7 = "SynFlooding:" ascii //weight: 2
        $x_2_8 = "WNetEnumCachedPasswords" ascii //weight: 2
        $x_2_9 = "spybot1.2c" ascii //weight: 2
        $x_2_10 = "startkeylogger" ascii //weight: 2
        $x_2_11 = "AVP_Crack.exe" ascii //weight: 2
        $x_2_12 = "zoneallarm_pro_crack.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Spybot_BY_2147600651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Spybot.BY"
        threat_id = "2147600651"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\RECYCLER\\msconfig32.exe" ascii //weight: 10
        $x_10_2 = "Bot killed and removed: %s (pid: %d)!" ascii //weight: 10
        $x_10_3 = "%s %s \"fo%d.net\" \"lol\" :%s" ascii //weight: 10
        $x_5_4 = "Patching tcpip.sys" ascii //weight: 5
        $x_5_5 = "cmd /c echo open %s %d >> ik &echo user %s %s >> ik &echo binary >> ik &echo get %s >> ik &echo bye >> ik &ftp -n -v -s:ik &del ik &%s &exit" ascii //weight: 5
        $x_1_6 = "Scanning: %s, %d threads. Scanning VNCs" ascii //weight: 1
        $x_1_7 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii //weight: 1
        $x_1_8 = "SYSTEM\\\\CurrentControlSet\\\\Services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\AuthorizedApplications\\\\List" ascii //weight: 1
        $x_1_9 = "RegSetValueExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

