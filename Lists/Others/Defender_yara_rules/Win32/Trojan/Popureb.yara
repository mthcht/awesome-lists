rule Trojan_Win32_Popureb_B_2147644806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popureb.B"
        threat_id = "2147644806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popureb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 78 6a 63 e8 ?? ?? ?? ?? 83 c4 08 50 6a 79 6a 62 e8 ?? ?? ?? ?? 83 c4 08 50 6a 7a 6a 61}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d1 89 55 fc 60 8b 45 fc c1 c8 03 c1 c8 04 89 45 fc 61 8b 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Popureb_F_2147646127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popureb.F"
        threat_id = "2147646127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popureb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 61 73 73 5f 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 6e 64 70 65 72 41 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 75 6e 44 65 6c 61 79 54 69 6d 65 00}  //weight: 1, accuracy: High
        $x_3_4 = {68 8d 34 10 e5}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Popureb_H_2147650484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popureb.H"
        threat_id = "2147650484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popureb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 26 c7 05 4c 00 00 00 06 01 67 26 8c 0d 4e 00 00 00 66 33 db}  //weight: 1, accuracy: High
        $x_1_2 = "hello_tt.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

