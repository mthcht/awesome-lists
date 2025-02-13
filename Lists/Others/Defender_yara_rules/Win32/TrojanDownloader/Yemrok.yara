rule TrojanDownloader_Win32_Yemrok_A_2147684277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yemrok.A"
        threat_id = "2147684277"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yemrok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 5c 00 2e 00 5c 00 66 00 75 00 63 00 6b 00 33 00 36 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_4 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

