rule TrojanDownloader_Win32_Bzub_IP_2147601115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bzub.IP"
        threat_id = "2147601115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7b 37 33 33 36 34 44 39 39 2d 31 32 34 30 2d 34 64 66 66 2d 42 31 31 41 2d 36 37 45 34 34 38 33 37 33 30 34 38 7d 00 00 7b 37 38 33 36 34 44 39 39 2d 41 32 34 30 2d 34 64 66 66 2d 42 31 31 41 2d 36 37 45 34 34 38 33 37 33 30 34 35 7d 00 00 7b 37 38 33 36 34 44 39 39 2d 41 36 34 30 2d 34 64 64 66 2d 42 39 31 41 2d 36 37 45 46 46 38 33 37 33 30 34 35 7d 00 00 7b 33 36 44 42 43 31 37 39 2d 41 31 39 46 2d 34 38 46 32 2d 42 31 36 41 2d 36 41 33 45 31 39 42 34 32 41 38 37}  //weight: 5, accuracy: High
        $x_1_2 = {00 6e 65 74 5f 69 6e 73 6c 6c 00 00 00 5c 69 70 76 36 6d 6f 6e 6c 2e 64 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

