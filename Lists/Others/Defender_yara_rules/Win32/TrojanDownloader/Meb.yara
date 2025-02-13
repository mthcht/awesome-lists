rule TrojanDownloader_Win32_Meb_A_2147625418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Meb.A"
        threat_id = "2147625418"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Meb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 11 59 e8 aa 02 00 00 90 e2 f8 68 6f 6e 00 00 68 75 72 6c 6d}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 59 e8 79 02 00 00 e2 f9 68 6c 33 32 00 68 73 68 65 6c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 04 03 5c ?? 2e 65 c7 44 03 04 78 65 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5b c6 07 b8 89 5f 01 66 c7 47 05 ff e0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

