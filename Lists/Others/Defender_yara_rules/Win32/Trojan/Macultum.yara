rule Trojan_Win32_Macultum_J_2147684701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Macultum.J"
        threat_id = "2147684701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Macultum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 77 69 6e 63 6f 6d 70 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 77 69 6e 2d 63 6f 6d 70 75 74 65 00}  //weight: 1, accuracy: High
        $x_10_3 = {00 62 6c 64 00 74 62 73 00 2e 63 00 00 6f 6d 00}  //weight: 10, accuracy: High
        $x_10_4 = "bldtbs.com/" ascii //weight: 10
        $x_10_5 = "(socks|http)=([^:]+):(\\d+)" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Macultum_A_2147684930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Macultum.gen!A"
        threat_id = "2147684930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Macultum"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 4e 6a 00 6a 04 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 01 00 00 00 85 c0 74 2d e8 ?? ?? ?? ?? 68 30 75 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {74 06 83 7d 08 01 75 0c 8b 55 dc c7 42 44 00 00 00 00 eb 0f 8b 45 dc}  //weight: 2, accuracy: High
        $x_1_3 = "X:\\projects\\px\\monitor\\Monitor.pdb" ascii //weight: 1
        $x_1_4 = "Mutual install | remove" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Macultum_B_2147684931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Macultum.gen!B"
        threat_id = "2147684931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Macultum"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 05 89 7d e8 eb 0f 33 c0 40 89 45 e8 83 f9 04 74 09 3b c8 74 05 ff 46 44}  //weight: 2, accuracy: High
        $x_2_2 = {74 36 6a 00 6a 04 8b ce e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 30 75 00 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 e6}  //weight: 2, accuracy: Low
        $x_1_3 = "wbt_media/mutualpublic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

