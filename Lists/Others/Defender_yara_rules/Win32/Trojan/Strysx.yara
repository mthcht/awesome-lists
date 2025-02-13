rule Trojan_Win32_Strysx_A_2147599284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strysx.A"
        threat_id = "2147599284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strysx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ff 00 00 00 6a 06 6a 03 68 ?? da 40 00 ff 15 ?? ?? 40 00 83 f8 ff a3 ?? ?? 41 00 74 6c 53 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7c 24 10 e8 ?? ff ff ff 8d 44 24 18 50 8b cf e8 ?? fe ff ff 8b 70 04 59 6a 00 8d 44 24 10 50 56 e8 ?? ?? 00 00 59 40 50 56 ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Strysx_B_2147599285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strysx.B"
        threat_id = "2147599285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strysx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 65 fc 00 8d 4d e0 c6 45 fc 01 e8 ?? ?? ?? ?? 6a 19 68 ?? ?? 02 10 8d 4d e0 e8 ?? ?? ?? ?? 83 65 fc 00 8d 4d e0 e8 ?? ?? ?? ?? 8d 75 e0 e8 ?? ?? ?? ?? b0 01 eb 18}  //weight: 2, accuracy: Low
        $x_1_2 = {c3 6a 09 58 c3}  //weight: 1, accuracy: High
        $x_1_3 = {6d 6f 64 5f 65 6d 61 69 6c 73 2e 64 6c 6c 00 5f 43 72 65 61 74 65 4d 6f 64 75 6c 65 40 30 00 5f 47 65 74 4d 6f 64 75 6c 65 49 64 40 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 41 73 55 73 65 72 00 5c 5c 2e 5c 50 69 70 65 5c [0-32] 00 53 4d 54 50 20 53 65 72 76 65 72 00 50 4f 50 33 20 53 65 72 76 65 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strysx_C_2147599286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strysx.C"
        threat_id = "2147599286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strysx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {eb ca 8d 75 e4 e8 ?? ?? 00 00 8d 4d b8 51 e8 ?? ?? 00 00 89 7d c8 ff 55 ec 8b 7d 08 89 45 b4 8b 10 57 8b c8 ff 52 ?? ff d3}  //weight: 3, accuracy: Low
        $x_1_2 = {62 6f 74 2e 64 6c 6c 00 5f 57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c 40 34 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 64 00 00 5f 43 72 65 61 74 65 4d 6f 64 75 6c 65 40 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 6f 63 6f 6c 2e 63 70 70 00 00 00 2e 6c 6f 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

