rule TrojanDownloader_Win32_Bubnix_A_2147630315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bubnix.A"
        threat_id = "2147630315"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bubnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 30 8b 4d 0c 56 8b 75 08 57 8a 16 ff 4d 10 32 d0}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 6a 0b 57 ff 75 08 ff 15 ?? ?? ?? ?? 8b d8 3b df 74 4c}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 61 70 70 6c 69 63 61 74 69 6f 6e 64 61 74 61 2e 62 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

