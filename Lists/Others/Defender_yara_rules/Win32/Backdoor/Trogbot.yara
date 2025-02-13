rule Backdoor_Win32_Trogbot_B_2147652546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trogbot.B"
        threat_id = "2147652546"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trogbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 dc 07 00 00 ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 83 c4 ?? 33 f6 ff d7 25 7f 00 00 80 79 05 48 83 c8 80 40 30 84 34 ?? ?? 00 00 83 c6 01 81 fe 00 28 00 00 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 04 53 6a 01 68 00 00 00 40 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 74 ?? 53 56 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 3d 00 50 00 00 76}  //weight: 2, accuracy: Low
        $x_1_3 = "Virtual SHELL v" ascii //weight: 1
        $x_1_4 = "\\isvc.pnf" ascii //weight: 1
        $x_1_5 = "ZCSVC" ascii //weight: 1
        $x_1_6 = "{%scmd%s: %s%s%s, %senginefilename%s: %s%s_%s.dat%s}" ascii //weight: 1
        $x_1_7 = {25 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 20 2d 20 25 73 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_8 = "[3504C036-D72C]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Trogbot_C_2147652555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trogbot.C"
        threat_id = "2147652555"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trogbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0e 33 c8 81 e1 ff 00 00 00 c1 e8 08 33 04 8d ?? ?? ?? ?? 46 83 ef 01 75 e5}  //weight: 2, accuracy: Low
        $x_1_2 = "GetSTProxyFromReg: " ascii //weight: 1
        $x_1_3 = {63 68 61 6c 6c 65 6e 67 65 00 00 00 63 68 61 6e 67 65 64 69 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 6c 6f 62 61 6c 5c 7b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d 00 00 00 7a 63 2e 6c 6f 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

