rule Trojan_Win32_Hokobot_A_2147693380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hokobot.A!dha"
        threat_id = "2147693380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 7d 0c 04 01 00 00 74 ?? 81 7d 0c 00 01 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = "##Data##: Active Window-->" ascii //weight: 10
        $x_10_3 = "SetWinHoK" ascii //weight: 10
        $x_10_4 = "<strong> [CAPLOCK] </strong>" ascii //weight: 10
        $x_1_5 = "\\serverhelp.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hokobot_B_2147693381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hokobot.B!dha"
        threat_id = "2147693381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MicrosoftServices" ascii //weight: 1
        $x_1_2 = "/c taskkill /f /PID" ascii //weight: 1
        $x_1_3 = "&copyme=5&xphpfile=" ascii //weight: 1
        $x_1_4 = "DLD-S:" ascii //weight: 1
        $x_1_5 = "DLD-E:" ascii //weight: 1
        $x_1_6 = "http://maktoob.yahoo.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Hokobot_A_2147693382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hokobot.A.dll!dha"
        threat_id = "2147693382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {3c 28 74 10 3c 29 74 0c 3c 2e 74 08 3c 20 74 04 3c}  //weight: 10, accuracy: High
        $x_10_2 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" ascii //weight: 10
        $x_10_3 = "220d5cc1" ascii //weight: 10
        $x_10_4 = "b9819c52" ascii //weight: 10
        $x_10_5 = "L$_RasDefaultCredentials#0" wide //weight: 10
        $x_10_6 = "SetWinHoK" ascii //weight: 10
        $x_1_7 = "\\Application Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hokobot_B_2147693383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hokobot.B.dll!dha"
        threat_id = "2147693383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\Profiler-P\\SmartSender\\wnhelp" ascii //weight: 100
        $x_1_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 50 49 44 20 00 00 00 4d 45 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = "Fdown" ascii //weight: 1
        $x_1_4 = "InetReadF" ascii //weight: 1
        $x_1_5 = "PathProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hokobot_C_2147693384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hokobot.C.dll!dha"
        threat_id = "2147693384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "serverhelp.dll" ascii //weight: 1
        $x_1_2 = "OpenClipFn" ascii //weight: 1
        $x_1_3 = "SetWinHoK" ascii //weight: 1
        $x_1_4 = "OpenClipboard" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

