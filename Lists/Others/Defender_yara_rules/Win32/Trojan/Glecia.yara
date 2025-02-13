rule Trojan_Win32_Glecia_A_2147624771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glecia.gen!A"
        threat_id = "2147624771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glecia"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 06 3f 46 c6 06 69 46 c6 06 64 46 c6 06 3d}  //weight: 2, accuracy: High
        $x_2_2 = {80 38 99 75 1e 80 78 01 99 75 18}  //weight: 2, accuracy: High
        $x_1_3 = {88 01 41 42 8a 02 84 c0 75 c6 88 01}  //weight: 1, accuracy: High
        $x_2_4 = {8b 4c 24 10 8a 1c 16 03 cf 30 19 46 3b f0 7e 02}  //weight: 2, accuracy: High
        $x_1_5 = {c7 46 28 4e 00 00 00 ff d7 68 ?? ?? ?? ?? 8d 46 40 50 c7 46 3c 4f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {80 38 53 75 71 89 45 f8 8d 45 fc 50 6a 40}  //weight: 1, accuracy: High
        $x_2_7 = {c6 03 26 8d 73 01 c6 06 63 46 c6 06 5b 46 c6 06 5d 46 c6 06 3d}  //weight: 2, accuracy: High
        $x_1_8 = {26 75 5b 5d 3d 26 64 5b 5d 3d 26 70 5b 5d 3d 00}  //weight: 1, accuracy: High
        $x_1_9 = {26 63 5b 5d 3d 26 74 5b 5d 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

