rule Trojan_Win32_Havokiz_A_2147936028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Havokiz.A"
        threat_id = "2147936028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Havokiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {2c 06 00 00 00 ?? ?? 48 ?? ?? 5c 06 00 00 00 ?? ?? ?? ?? ?? ?? 48 8b ?? 5c 06 00 00 ?? f6 99 5a 2e e8 ?? ?? ?? ?? 48 8b ?? 48 ?? ?? 4c 02 00 00 48 8b ?? 5c 06 00 00 ?? 23 db 07 03 e8 ?? ?? ?? ?? 48 8b ?? 48 ?? ?? 44 02 00 00 48 8b ?? 5c 06 00 00 ?? da 81 b3 c0 e8 ?? ?? ?? ?? 48 8b ?? 48 ?? ?? 54 02 00 00 48 8b ?? 5c 06 00 00 ?? d7 71 ba 70 e8 ?? ?? ?? ?? 48 8b ?? 48 ?? ?? 64 02 00 00 48 8b ?? 5c 06 00 00 ?? 88 2b 49 8e e8 ?? ?? ?? ?? 48 8b ?? 48 ?? ?? 84 02 00 00 48 8b ?? 5c 06 00 00 ?? ef f0 a1 3a e8 aa 00 48}  //weight: 16, accuracy: Low
        $x_1_2 = {01 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 03 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? c4 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ce 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? d8 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 34 08 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 16 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 18 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 1a 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 28 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 00 00 d4 00 0b 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 64 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 15 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 10 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 0c 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? [0-12] 0f 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 14 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f6 99 5a 2e}  //weight: 1, accuracy: High
        $x_1_4 = {da 81 b3 c0}  //weight: 1, accuracy: High
        $x_1_5 = {d7 71 ba 70}  //weight: 1, accuracy: High
        $x_1_6 = {88 2b 49 8e}  //weight: 1, accuracy: High
        $x_1_7 = {ef f0 a1 3a}  //weight: 1, accuracy: High
        $x_1_8 = {f5 39 34 7c}  //weight: 1, accuracy: High
        $x_1_9 = {2a 92 12 d8}  //weight: 1, accuracy: High
        $x_1_10 = {8d f1 4f 84}  //weight: 1, accuracy: High
        $x_1_11 = {5b bc ce 73}  //weight: 1, accuracy: High
        $x_1_12 = {59 24 93 b8}  //weight: 1, accuracy: High
        $x_1_13 = {02 9e d0 c2}  //weight: 1, accuracy: High
        $x_1_14 = {e5 36 26 ae}  //weight: 1, accuracy: High
        $x_1_15 = {5c 3c b4 f3}  //weight: 1, accuracy: High
        $x_1_16 = {2f 87 d8 1c}  //weight: 1, accuracy: High
        $x_1_17 = {d7 53 22 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((16 of ($x_1_*))) or
            ((1 of ($x_16_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Havokiz_SC_2147936029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Havokiz.SC"
        threat_id = "2147936029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Havokiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 48 89 e6 48 83 e4 f0 48 83 ec 20 e8 0f 00 00 00 48 89 f4 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {65 48 8b 04 25 60 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Havokiz_C_2147936030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Havokiz.C"
        threat_id = "2147936030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Havokiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 81 ec f8 04 00 00 48 8d 7c 24 78 44 89 8c 24 58 05 00 00 48 8b ac 24 60 05 00 00 4c 8d 6c 24 78 f3 ab b9 59 00 00 00 48 c7 44 24 70 00 00 00 00 c7 44 24 78 68 00 00 00 c7 84 24 b4 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

