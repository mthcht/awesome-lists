rule Trojan_Win32_ChChes_A_2147723449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChChes.A!dha"
        threat_id = "2147723449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChChes"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 0c 8b 4d 08 2b d1 56 57 6a 04 5e 6a 04 5f 8a 04 0a 30 01 41 83 ef 01 75 ?? 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 8b 7d 08 6a ?? 59 6a ?? 5a 33 f6 8d 04 32 25 ?? ?? ?? ?? 79 ?? 48 83 c8 ?? 40 03 c1 8a 04 38 88 44 35 08 46 83 fe ?? 7c ?? 8b 45 08 4a 89 04 39 83 c1 ?? 85 d2 7f ?? 5f 5e}  //weight: 1, accuracy: Low
        $n_2_3 = "Release\\Huya" ascii //weight: -2
        $n_2_4 = "hydevice.pdb" ascii //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ChChes_B_2147730364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChChes.B!dha"
        threat_id = "2147730364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChChes"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Release\\kugou.pdb" ascii //weight: 1
        $x_1_2 = "\\VM\\WirteBlackSafe_" ascii //weight: 1
        $x_1_3 = "\\win.dat" wide //weight: 1
        $x_1_4 = "CreateProcess err3 %s errid:%d" wide //weight: 1
        $x_1_5 = "fengyue0" wide //weight: 1
        $x_1_6 = "IDA: Quick start" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_ChChes_G_2147730365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChChes.G!dha"
        threat_id = "2147730365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChChes"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 db 74 19 8d 14 3e 8b 7d fc 8a 0c 11 32 0c 38 40 8b 7d 10 88 0a 8b 4d 08 3b c3 72 e7 3b 75 f8 76 0e 57 68 ?? ?? ?? ?? e8 31 00 00 00 83 c4 08 8b 45 0c 46 8b 4d 08 3b f0 72 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ChChes_G_2147730365_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChChes.G!dha"
        threat_id = "2147730365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChChes"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 14 3e 8b 7d ?? 8a 0c 11 32 0c 38 40 8b 7d ?? 88 0a 8b 4d ?? 3b c3 72 e7}  //weight: 5, accuracy: Low
        $x_5_2 = {41 83 f9 04 7c ce 2c 00 0f b6 81 ?? ?? ?? ?? 30 44 0d ?? 0f b6 81 ?? ?? ?? ?? 30 44 0d ?? 0f b6 81 ?? ?? ?? ?? 30 44 0d ?? 0f b6 81 ?? ?? ?? ?? 30 44 0d}  //weight: 5, accuracy: Low
        $x_3_3 = {0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 41 83 f9 04 7c ba}  //weight: 3, accuracy: Low
        $x_3_4 = {0f b6 4c 06 fc 30 4c 05 ?? 0f b6 0c 06 30 4c 05 ?? 0f b6 4c 06 04 30 4c 05 ?? 0f b6 4c 06 08 30 4c 05 ?? 40 83 f8 04 7c d7 85 db 74 09 8d 45 ?? 50 e8}  //weight: 3, accuracy: Low
        $x_10_5 = {8d 00 8d 00 8d 00 8d 00 8d 00 8d 33 c0 33 c9 85 d2 74 17 57 8d a4 24 00 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {c7 45 9c 61 62 65 32 c7 45 a0 38 36 39 66 c7 45 a4 2d 39 62 34}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

