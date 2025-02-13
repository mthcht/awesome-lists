rule TrojanDownloader_Win32_Rustock_A_2147628326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rustock.A"
        threat_id = "2147628326"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 0e 8a c1 c0 e0 04 32 c1 c0 e0 03 d0 e9 32 c1 b1 03 f6 e9 00 45 ?? 46 4f 75 e2}  //weight: 2, accuracy: Low
        $x_1_2 = {74 a1 8b 45 fc 3b 45 f8 75 99}  //weight: 1, accuracy: High
        $x_1_3 = {8b f8 3b fe 74 24 39 75 0c 74 0b 56}  //weight: 1, accuracy: High
        $x_1_4 = {67 6c 61 69 64 65 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

