rule PWS_Win32_Pemsepos_A_2147622750_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pemsepos.A"
        threat_id = "2147622750"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pemsepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e0 8b 7d 0c 3b c7 73 10 8b 4d 08 0f b6 14 08 83 f2 ?? 88 14 08 40 eb e6}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 44 24 28 03 44 24 40 03 44 24 3c c1 e0 12 33 44 24 10 31 44 24 04 b8 06 00 00 80 0f a2 31 4c 24 04 8b 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

