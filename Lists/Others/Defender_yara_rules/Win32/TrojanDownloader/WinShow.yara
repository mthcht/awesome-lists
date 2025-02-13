rule TrojanDownloader_Win32_WinShow_H_2147804045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WinShow.gen!H"
        threat_id = "2147804045"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WinShow"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 46 65 61 74 32 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 2, accuracy: High
        $x_1_2 = {46 65 61 74 32 20 55 70 64 61 74 65 72 20 34 37 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 46 65 61 74 32 43 6f 6e 66 69 67 4d 65 6d 6f 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

