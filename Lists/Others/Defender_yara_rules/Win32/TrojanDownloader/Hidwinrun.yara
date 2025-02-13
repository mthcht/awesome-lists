rule TrojanDownloader_Win32_Hidwinrun_A_2147607554_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hidwinrun.A"
        threat_id = "2147607554"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hidwinrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 48 52 55 4e 56 45 52 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_2 = {00 48 54 54 50 47 45 54 44 41 54 41 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_3 = "%02x%02x%02x%02x%02x%02x" ascii //weight: 1
        $x_1_4 = {25 73 5c 48 69 64 65 49 6e 73 74 61 6c 6c 65 72 5f 75 70 25 64 2e 65 78 65 00 00 00 53 6f 66 74 77 61 72 65 5c 25 73}  //weight: 1, accuracy: High
        $x_1_5 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

