rule Trojan_Win32_Metibh_A_2147610399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Metibh.A"
        threat_id = "2147610399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Metibh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SysDown%ld" ascii //weight: 1
        $x_1_2 = {5f 45 78 70 6c 6f 72 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {5f 57 69 6e 6c 6f 67 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 73 47 61 6d 65 50 6c 61 79 65 72 00}  //weight: 1, accuracy: High
        $x_4_5 = {51 8b 44 24 08 56 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 05 33 c0 5e 59 c3 8d 4c 24 04 6a 00 51 8d 54 24 14 6a 02 52 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 33 c0 66 81 7c 24 0c 4d 5a 5e 0f 94 c0 59 c3}  //weight: 4, accuracy: Low
        $x_3_6 = {8b 4c 24 04 81 ec 40 01 00 00 8d 44 24 00 50 51 ff 15 ?? ?? ?? ?? 83 f8 ff 75 09 33 c0 81 c4 40 01 00 00 c3 50 ff 15 ?? ?? ?? ?? 8b 44 24 00 f6 d0 25 ff 00 00 00 c1 e8 04 83 e0 01 81 c4 40 01 00 00 c3}  //weight: 3, accuracy: Low
        $x_3_7 = {8d 4c 24 10 6a 01 51 56 ff d7 6a 04 8d 54 24 14 6a 00 52 ff d7 8b 84 24 ?? ?? ?? 00 6a 00 56 50 ff 15 ?? ?? ?? ?? 5f 5b 6a 07 56}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

