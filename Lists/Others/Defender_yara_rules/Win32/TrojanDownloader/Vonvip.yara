rule TrojanDownloader_Win32_Vonvip_A_2147629518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vonvip.A"
        threat_id = "2147629518"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonvip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 61 75 64 69 6f 64 67 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 77 77 77 2e 73 68 6c 65 74 7a 2e 63 6f 2e 63 63 2f 64 72 6f 75 2f 63 62 2e 65 78 65 00 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 61 73 70 65 6c 2e 65 78 65 00 68 74 74 70 3a 2f 2f 39 35 2e 32 31 31 2e 39 36 2e 32 33 31 2f 69 63 76 6f 6e 2e 65 78 65 00 fd 99 80 5c 53 4d 53 63 76 68 6f 73 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 39 35 2e 32 31 31 2e 39 36 2e 32 33 31 2f 65 72 76 69 70 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

