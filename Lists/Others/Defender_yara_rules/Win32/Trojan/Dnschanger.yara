rule Trojan_Win32_Dnschanger_L_2147630737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dnschanger.L"
        threat_id = "2147630737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dnschanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7c 24 1c b9 03 00 00 00 be ?? ?? 40 00 33 ?? f3 a6}  //weight: 3, accuracy: Low
        $x_3_2 = {8b c8 b8 f1 f0 f0 f0 81 f1 e9 e3 2e 01}  //weight: 3, accuracy: High
        $x_3_3 = {c1 ea 04 83 c2 02 b8 c1 c0 c0 c0 f7 e2}  //weight: 3, accuracy: High
        $x_1_4 = "DNSService" ascii //weight: 1
        $x_1_5 = "ini-in here" ascii //weight: 1
        $x_1_6 = "NET STOP \"%S\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dnschanger_M_2147649618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dnschanger.M"
        threat_id = "2147649618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dnschanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/files/count.jpg" ascii //weight: 1
        $x_1_2 = "\\Network\\Connections\\Pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_3 = {25 73 5c 25 63 25 63 25 63 25 63 25 63 2e 25 73 [0-16] 25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 [0-16] 68 74 6d 6c 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_4_4 = {8b c1 c6 07 ?? 2b c7 89 77 01 03 c6 75 ?? 8b c1 2b d8 c6 01 e8 8d 44 33 ?? 89 41 01 8d 46 fc bb ?? ?? ?? 00 89 85 ?? ?? ?? ff 8d 45 ?? 50 6a 40 53 56 ff 75 ?? 89 b5 ?? ?? ?? ff ff 15 ?? ?? ?? 00 85 c0 75 ?? ff 15}  //weight: 4, accuracy: Low
        $x_4_5 = {59 33 c0 8d bd ?? ?? ?? ff 80 a5 ?? ?? ?? ?? ?? f3 ab 66 ab aa 6a 3f 33 c0 59 8d bd ?? ?? ?? ff f3 ab 8b 35 ?? ?? ?? 00 68 ?? ?? ?? 00 66 ab aa 8b 7d 0c 8d 85 ?? ?? ?? ff 50 89 7d ?? ff ?? 8d 85 ?? ?? ?? ff 50 8d 85 ?? ?? ?? ff 68 ?? ?? ?? 00 50 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dnschanger_AM_2147650746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dnschanger.AM"
        threat_id = "2147650746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dnschanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".php?user=gonzik&agent=" wide //weight: 3
        $x_2_2 = "alpha_ru" wide //weight: 2
        $x_2_3 = "foodlabs.ru" wide //weight: 2
        $x_1_4 = ".DNSServerSearchOrder" wide //weight: 1
        $x_1_5 = ".SetDNSServerSearchOrder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dnschanger_AN_2147658676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dnschanger.AN"
        threat_id = "2147658676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dnschanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Win32_NetworkAdapterConfiguration Where IPEnabled=TRUE" wide //weight: 1
        $x_1_2 = "netsh interface ip set dns name=" wide //weight: 1
        $x_1_3 = {2e 00 61 00 73 00 70 00 3f 00 69 00 64 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 6d 00 61 00 63 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 76 00 65 00 72 00 3d 00 31 00 2e 00 30 00}  //weight: 1, accuracy: Low
        $x_1_4 = "cmd_getfile|" wide //weight: 1
        $x_1_5 = {73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 73 00 74 00 61 00 74 00 69 00 63 00 ?? ?? 61 00 64 00 64 00 72 00 3d 00}  //weight: 1, accuracy: Low
        $x_6_6 = "winner!" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

