rule VirTool_Win32_Vanti_B_2147604776_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vanti.B"
        threat_id = "2147604776"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 00 00 01 00 [0-64] (81 fb 00 00|83) [0-80] 75 [0-80] 66 81 38 50 45 [0-80] 81 3a 4b 45 52 4e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 2c 8b 74 24 14 51 6a 01 53 8d 14 1e ff d2 8b c6}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\drivers\\ntfs.sys" ascii //weight: 1
        $x_2_4 = {68 5c 64 72 69 e8 ?? ?? 00 00 8f 02 e8 [0-48] 68 76 65 72 73 e8 [0-80] 68 6e 74 66 73 e8 [0-48] 68 2e 73 79 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Vanti_B_2147606297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vanti.gen!B"
        threat_id = "2147606297"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec bb 00 [0-40] 81 c3 00 00 01 00 [0-80] 83 f9 00 74 [0-64] 66 81 (38|2d|3b) 4d 5a [0-80] 83 f8 00 [0-64] 81 3a 4b 45 52 4e [0-48] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vanti_C_2147609365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vanti.gen!C"
        threat_id = "2147609365"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 41 56 3b 52 41 56 3b 41 56 50 3b 4b 41 56 53 56 43 3b 00}  //weight: 1, accuracy: High
        $x_1_2 = "KAVsys" ascii //weight: 1
        $x_1_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 48 49 44 45 50 52 45 46 49 58 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 e6 ff ff 00 00 68 ?? ?? ?? ?? 33 c6 6a 00 68 03 00 1f 00 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 5e 0f 85 91 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

