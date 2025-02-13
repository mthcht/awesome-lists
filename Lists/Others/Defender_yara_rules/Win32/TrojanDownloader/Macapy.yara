rule TrojanDownloader_Win32_Macapy_A_2147721097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Macapy.A!bit"
        threat_id = "2147721097"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Macapy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 26 8b 04 f5 ?? ?? ?? 00 8a 0c f5 ?? ?? ?? 00 0f b7 d3 f6 d1 32 0c 10 32 cb 43 88 0c 3a 66 3b 1c f5 ?? ?? ?? 00 72 da}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 1f 33 c1 c1 e9 08 25 ff 00 00 00 33 0c 85 ?? ?? ?? 00 47 3b fa 72 e6}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 0c 9e 03 4c 37 20 74 16 8b 09 03 ce e8 ?? ?? ?? ff 8b d0 e8 ?? ?? ?? ff 3b 44 ?? ?? 74 14 43 3b 5c 37 18 72 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

