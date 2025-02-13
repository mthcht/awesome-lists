rule TrojanDownloader_Win32_Psloader_B_2147734156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Psloader.B"
        threat_id = "2147734156"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Psloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AppGetLoader.jpg" wide //weight: 1
        $x_1_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 31 39 32 2e 39 39 2e 31 37 35 2e 31 32 33 [0-32] 2e 7a 69 70 27 2c 27 43 3a 5c 48 41 4c 39 54 48 [0-32] 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_3 = "HAL9TH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

