rule TrojanDownloader_Win32_FakeIA_A_2147799813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeIA.A"
        threat_id = "2147799813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "23"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05 53}  //weight: 1, accuracy: High
        $x_1_2 = {83 fb 32 7d 14 50 53 8b 45 0c 50 56}  //weight: 1, accuracy: High
        $x_1_3 = {53 68 2e 70 6e 67 00 02 00 69}  //weight: 1, accuracy: Low
        $x_1_4 = "Insecure Browsing Error:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

