rule Trojan_Win32_Iflar_C_2147623147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iflar.gen!C"
        threat_id = "2147623147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iflar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 8d 45 f0 68 ?? ?? ?? 00 50 e8 ?? ?? ff ff 8b 5d f0 83 c4 14 53 57 6a 01 57 ff 15 ?? ?? ?? 00 83 f8 ff 89 86 ?? 02 00 00 0f 95 c0 88 86 ?? 02 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {41 43 55 45 49 4c 4c 49 52 4d 49 58 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 66 75 63 6b 6c 61 72 67 65 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 76 63 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 79 73 74 65 6d 44 65 6c 65 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Iflar_18068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iflar"
        threat_id = "18068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iflar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 54 09 00 00 59 6a 01 be ?? ?? ?? 00 5b 8d 4d f0 56 89 5d fc e8 ?? ?? 01 00 56 8d 4d ec c6 45 fc 02 e8 ?? ?? 01 00 85 c0 7c 12 8b 4d 08 68 ?? ?? ?? 00 e8 ?? ?? 01 00 89 5d e8 eb 14 8d 45 f0 68 ?? ?? ?? 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {50 8d 45 f0 68 ?? ?? ?? 00 50 e8 ?? ?? 01 00 83 c4 14 ff 75 f0 53 6a 01 53 ff 15 ?? ?? ?? 00 83 f8 ff 89 86 ?? 01 00 00 75 08 88 9e ?? 01 00 00 eb 07 c6 86 ?? 01 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Iflar_18068_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iflar"
        threat_id = "18068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iflar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 54 09 00 00 59 6a 01 be ?? ?? ?? 00 5b 8d 4d f0 56 89 5d fc e8 ?? ?? 01 00 56 8d 4d ec c6 45 fc 02 e8 ?? ?? 01 00 85 c0 7c 12 8b 4d 08 68 ?? ?? ?? 00 e8 ?? ?? 01 00 89 5d e8 eb 14 8d 45 f0 68 ?? ?? ?? 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {50 8d 45 f0 68 ?? ?? ?? 00 50 e8 ?? ?? 01 00 83 c4 14 ff 75 f0 53 6a 01 53 ff 15 ?? ?? ?? 00 83 f8 ff 89 86 ?? (01|02) 00 00 75 08 88 9e ?? 01 00 00 eb 07 c6 86 ?? 01 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

