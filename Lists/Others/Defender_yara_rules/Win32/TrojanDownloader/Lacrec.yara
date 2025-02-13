rule TrojanDownloader_Win32_Lacrec_A_2147611328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lacrec.A"
        threat_id = "2147611328"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lacrec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 eb 8b 80 3d ?? ?? ?? ?? 01 75 4c 68 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_2_2 = {80 7c 18 ff 3b 75 45 8d 04 b5 ?? ?? ?? ?? 50 8b cb 49 ba 01 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {43 4f 43 4c 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 65 67 43 6f 6d 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

