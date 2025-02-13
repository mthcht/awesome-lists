rule DoS_Win32_LasainWpr_A_2147813896_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/LasainWpr.A!dha"
        threat_id = "2147813896"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "LasainWpr"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 [0-26] 5c 00 5c 00 2e 00 5c 00 [0-26] 2a 00 2e 00 2a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {54 00 6d 00 66 00 00 00 54 00 6d 00 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b d1 c1 ea ?? 33 d1 69 ca ?? ?? ?? ?? 03 c8 89 8c ?? ?? ?? ?? ?? 40 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {00 8b c1 25 ad ?? ?? ?? ?? c1 e0 ?? 33 c8 8b c1 25 ?? ?? ?? ?? c1 e0 ?? 33 c8 8b c1 c1 e8 ?? 33 c1 89 06 83 c6 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

