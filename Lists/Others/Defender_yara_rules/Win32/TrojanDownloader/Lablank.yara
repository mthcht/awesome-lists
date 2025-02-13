rule TrojanDownloader_Win32_Lablank_A_2147624039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lablank.A"
        threat_id = "2147624039"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lablank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "http://blank.la" ascii //weight: 2
        $x_1_2 = "06926B30-424E-4f1c-8EE3-543CD96573DC" ascii //weight: 1
        $x_1_3 = "1FBA04EE-3024-11D2-8F1F-0000F87ABD16" ascii //weight: 1
        $x_2_4 = {6a 01 68 d0 07 00 00 ff 15 ?? ?? 40 00 [0-16] 50 [0-16] 50 ff [0-16] 83 c4 0c [0-32] 6a 01 [0-16] 50 68 02 00 00 80 ff 15 ?? ?? 40 00 [0-32] 6a 20 [0-16] 50 e8 [0-16] 50 e8 [0-32] 6a 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

