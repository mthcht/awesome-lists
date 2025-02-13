rule Trojan_Win32_Newspy_A_2147697423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Newspy.A"
        threat_id = "2147697423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Newspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 0c 41 3a 5c 00 33 db 8d 4b 41}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f4 8a 14 11 f6 da 30 14 38 40 41 3b 45 f8 72 e8}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 20 25 73 20 62 75 69 6c 64 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "filename=\"file.raw\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Newspy_B_2147708679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Newspy.B!bit"
        threat_id = "2147708679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Newspy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 25 ?? ?? ?? ?? 33 d2 bb ?? ?? ?? ?? f7 f3 41 0a c3 2a c2 30 44 0f ff 8b 45 ?? 3b c8 72 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

