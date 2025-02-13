rule TrojanDownloader_Win32_Neptaven_A_2147598386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neptaven.A"
        threat_id = "2147598386"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neptaven"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 02 00 00 80 c7 45 d0 57 61 72 65 c7 45 d4 5c 4d 69 63}  //weight: 3, accuracy: High
        $x_3_2 = {33 c9 39 4c 24 08 7e 10 8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 7c f0 c3 55 8b ec 83 ec 1c}  //weight: 3, accuracy: Low
        $x_1_3 = {8d 45 d8 c7 45 d8 4f 70 65 6e 50}  //weight: 1, accuracy: High
        $x_1_4 = {40 00 2e 65 78 65 56 50 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {40 00 2e 64 6c 6c 56 50 ff 15}  //weight: 1, accuracy: High
        $x_1_6 = {53 68 80 00 00 00 6a 02 53 6a 01 68 00 00 00 40 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

