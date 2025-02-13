rule Worm_Win32_Seykr_A_2147685086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Seykr.A"
        threat_id = "2147685086"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Seykr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 02 6a 00 6a 56 e8 ?? ?? ?? ?? 6a 00 6a 02 6a 00 6a 11 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 0d e8 ?? ?? ?? ?? 6a 00 6a 02 6a 00 6a 0d e8}  //weight: 1, accuracy: Low
        $x_1_2 = {00 53 6b 79 70 65 [0-16] 46 61 63 65 62 6f 6f 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 26 73 74 61 72 74 20 65 78 70 6c 6f 72 65 72 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

