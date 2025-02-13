rule Trojan_Win32_Duqu_A_2147650510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu.A"
        threat_id = "2147650510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" wide //weight: 1
        $x_1_2 = {8a 4d 08 88 48 08 88 58 09 8b 00 8b 10 8b c8 ff 52 04}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 0c 03 c6 30 08 c1 c9 ?? 8b c1 0f af c1 33 d2 bf ?? ?? ?? ?? f7 f7 8b d1 69 d2 ?? ?? ?? ?? 8d 44 10 01 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Duqu_B_2147650511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu.B"
        threat_id = "2147650511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 ff 75 0c 51 56 8d 4d ?? 51 57 ff d0 85 c0 74 0d 6a 01 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 8b 45 0c 0f b7 40 06 ff 45 f8 83 45 fc 28 83 c6 28 39 45 f8 7c ?? 8b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Duqu_E_2147650972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu.E"
        threat_id = "2147650972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 02 06 24 ae 74 07 33 c0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 01 ba ?? ?? ?? ?? 66 33 c2 8b 54 24 08 66 89 02 74 16 57 41 41 66 8b 01 42 42 bf ?? ?? ?? ?? 66 33 c7 66 89 02 75 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

