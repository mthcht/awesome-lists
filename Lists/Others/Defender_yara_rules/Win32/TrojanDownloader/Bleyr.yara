rule TrojanDownloader_Win32_Bleyr_A_2147660469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bleyr.A"
        threat_id = "2147660469"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bleyr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 33 c0 83 e1 03 f3 a4 b9 3f 00 00 00 8d bc 24 ?? 00 00 00 f3 ab 66 ab aa 8d 7c 24 10 83 c9 ff 33 c0 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa 33 d2 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d bc 24 ?? 00 00 00 83 c9 ff f2 ae f7 d1 49}  //weight: 5, accuracy: Low
        $x_1_2 = "/f /t /im AYServiceNt.aye" ascii //weight: 1
        $x_1_3 = "%s?userid=%s&mac=%s&ver=%s&os=%s&flag=%d" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6e 65 77 64 65 73 6b 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

