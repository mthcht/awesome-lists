rule TrojanSpy_Win32_Banzornk_A_2147691678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banzornk.A"
        threat_id = "2147691678"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banzornk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4d 6f 64 75 6c 65 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 4, accuracy: High
        $x_2_2 = {56 50 53 e8 01 00 00 00 cc 58 89 c3 40 2d 00 ?? ?? 00 2d 00 82 0c 10 05 f7 81 0c 10 80 3b cc 75 19 c6 03 00 bb 00 10 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 4d 0c c1 e9 02 8b 45 10 8b 5d 14 85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb f2 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

