rule Worm_Win32_Lemoor_A_2147602792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lemoor.gen!A"
        threat_id = "2147602792"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lemoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 50 53 e8 ?? ?? 00 00 e8 ?? ?? 00 00 8b 3d ?? ?? ?? ?? 89 87 2c 01 00 00 66 a3 ?? ?? ?? ?? 66 35 96 96 66 a3 ?? ?? ?? ?? 56 68 02 02 00 00 e8 ?? ?? 00 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 05 00 00 00 01 00 00 00 0f 68 01 00 00 98 53 e8 ?? ?? 00 00 6a 00 6a 20 57 53 e8 ?? ?? 00 00 66 81 7f 16 01 bd}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 44 24 02 03 ff 6a 10 57 53 e8 ?? ?? 00 00 0b c0 74 02 8b 00 e8 ?? ?? 00 00 6a 00 6a 07 e8 ?? ?? 00 00 55 53 45 52 20 32 0a 00 53 e8 ?? ?? 00 00 e8 ?? ?? 00 00 6a 00 6a 07}  //weight: 1, accuracy: Low
        $x_1_4 = {c3 50 4f 52 54 20 ff eb 11 8b 34 24 33 c9 66 81 c1 a3 01 80 36 96 46 e2 fa c3 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {45 70 68 65 6d 65 72 61 6c [0-16] 54 72 65 65 48 75 67 67 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

