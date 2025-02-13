rule Trojan_Win32_Riern_A_2147627627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Riern.A"
        threat_id = "2147627627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Riern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 5e 89 45 fc 8b 75 fc 85 f6 74 2f 68 48 1e 35 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Riern_B_2147629978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Riern.B"
        threat_id = "2147629978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Riern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 ff d7 89 45 e4 8d 85 ?? ?? ff ff 68 ?? ?? 40 00 50 e8 ?? ?? ?? ?? 59}  //weight: 1, accuracy: Low
        $x_1_2 = {50 ff 55 fc 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 ff 55 f8 6a 08 8d 85 ?? ?? ff ff 6a 00 50 ff 55 e8 8d 85 ?? ?? ff ff 50 56 ff 55 f4 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Riern_H_2147638540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Riern.H"
        threat_id = "2147638540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Riern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 32 32 cb 88 0c 2e 46 3b 74 24 ?? 0f 8c ?? ?? ?? ?? 5b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 88 1c 29 89 7e ?? 5d 39 56 ?? 72 02 8b 00 c6 04 38 00 8b c6}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 68 01 8d 49 00 8a 08 40 3a cb 75 f9 2b c5 50}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 10 01 00 00 00 39 ?? ?? ?? 72 0a 8b ?? ?? ?? 89 ?? ?? ?? eb 08 8d ?? ?? ?? 89 [0-9] 8d ?? ?? ?? ?? 6a 01 ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Riern_I_2147638745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Riern.I"
        threat_id = "2147638745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Riern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 39 32 d3 88 14 3e 47 3b 7c ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 91 10 01 00 00 68 f2 0a 00 00 6a 40 ff d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Riern_L_2147649502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Riern.L"
        threat_id = "2147649502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Riern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 69 64 65 62 61 72 2e 65 78 65 00 73}  //weight: 10, accuracy: High
        $x_10_2 = {8b b4 bc 18 01 00 00 3b f5 0f 84 ?? 00 00 00 68 04 01 00 00 8d 44 24 18 6a 00 50 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b [0-5] 83 c4 0c 56 6a 00 68 10 04 00 00 ff d2}  //weight: 10, accuracy: Low
        $x_1_3 = {8b 5f 14 03 da 3b d9 76 20 83 [0-2] 10 72 02 8b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 5e 14 03 da 3b d9 76 19 83 ff 10 72 02 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Riern_M_2147649905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Riern.M"
        threat_id = "2147649905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Riern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c eb ?? ff 75 0c 57 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c 39 7d 10 74 ?? 39 75 0c 73 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {56 53 53 6a 1a 53 ff d0 3b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

