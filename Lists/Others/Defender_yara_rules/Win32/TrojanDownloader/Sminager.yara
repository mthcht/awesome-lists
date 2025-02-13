rule TrojanDownloader_Win32_Sminager_F_2147723877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sminager.F"
        threat_id = "2147723877"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sminager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 75 6e 20 22 63 6d 64 20 2f 63 20 62 69 74 73 61 64 6d 69 6e 20 2f 54 72 61 6e 73 66 65 72 20 6d 79 44 6f 77 6e 6c 6f 61 64 4a 6f 62 20 22 22 68 74 74 70 3a 2f 2f 66 6f 72 65 67 72 6f 75 6e 64 2e 6d 65 2f 6d 2f 01 00 2e 69 63 6f 22 22 20 22 22 25 63 64 25 5c 05 00 2e 76 62 73 22 22 20 26 26 20 05 00 2e 76 62 73 22 2c 20 30 2c 20 66 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

