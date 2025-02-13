rule Trojan_Win32_Tromp_A_2147595044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tromp.A"
        threat_id = "2147595044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tromp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 64 6c 6c 2e 64 6c 6c 00 4e 74 51 75 65 72 79}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 fc 03 40 3c 8b 80 80 00 00 00 03 45 fc 89 45 f8 89 c6 8b 50 0c 89 d0 03 55 fc 85 c0 74}  //weight: 2, accuracy: High
        $x_1_3 = {40 00 8d 55 fc 52 6a 04 6a 20 50 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? bf ?? ?? ?? ?? b9 20 00 00 00 f3 a4 8b 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {74 00 61 00 73 00 6b 00 64 00 69 00 72 00 00 00 74 00 61 00 73 00 6b 00 64 00 69 00 72 00 00 00 61 64 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

