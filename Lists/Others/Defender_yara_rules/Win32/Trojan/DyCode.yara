rule Trojan_Win32_DyCode_A_2147639888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DyCode.A"
        threat_id = "2147639888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DyCode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bd 4b 48 43 42 66 b8 04 00 [0-2] cc}  //weight: 2, accuracy: Low
        $x_1_2 = {50 6a 40 8b 45 ?? 50 8b 45 fc 50 ff 15 ?? ?? ?? ?? 8b 45 fc ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 03 c3 e8 ?? ?? ?? ?? 5a 5b c3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d ?? ?? ?? ?? 88 c3 32 de c1 e8 08 33 04 9d ?? ?? ?? ?? c1 ea 10}  //weight: 1, accuracy: Low
        $x_1_5 = {53 48 45 4c 4c 00 00 00 43 4f 44 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DyCode_C_2147642520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DyCode.C"
        threat_id = "2147642520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DyCode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 10 64 ff 35 30 00 00 00 81 6d c8 6b 1e 01 00 8b 3d ?? ?? ?? 00 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {66 bf 80 00 be ef 00 00 00 bf fb 00 00 00 b9 a5 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DyCode_D_2147642618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DyCode.D"
        threat_id = "2147642618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DyCode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 8b c8 81 e9 ae f6 ff ff 51}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 c4 e8 03 ?? f7 ?? ?? c9 c2 28 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 c0 07 03 ?? 41 80 39 00 e9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

