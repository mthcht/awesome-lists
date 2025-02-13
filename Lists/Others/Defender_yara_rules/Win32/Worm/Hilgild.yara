rule Worm_Win32_Hilgild_A_2147637863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hilgild!gen.A"
        threat_id = "2147637863"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hilgild"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 3e 8a c8 8a d0 c0 f9 03 80 e2 0e 80 e1 0e c0 e2 03 0a ca 24 81 0a c8 88 0c 3e 46 3b f5 7c df}  //weight: 2, accuracy: High
        $x_2_2 = {68 3f 77 1b 00 ff ?? ?? ?? 40 00 e9}  //weight: 2, accuracy: Low
        $x_1_3 = {47 48 49 5f 42 41 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 68 75 6d 62 73 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 45 4c 6c 4f 20 4d 79 62 41 62 59 21 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 4c 56 45 52 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

