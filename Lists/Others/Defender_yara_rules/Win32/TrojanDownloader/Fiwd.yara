rule TrojanDownloader_Win32_Fiwd_A_2147608743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fiwd.A"
        threat_id = "2147608743"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiwd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 c1 ee 06 ff d7 83 c4 04 8b f8 ff 15 ?? ?? ?? ?? 03 f8 57 ff 15 [0-10] ff d5 99 b9 c0 5d 00 00 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {68 51 46 00 00 c7 44 24 18 51 46 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 4f 53 54 00 00 00 00 57 69 6e 64 6f 77 73 4d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 6f 63 6b 73 2e 65 78 65 00 74 69 6d 65 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

