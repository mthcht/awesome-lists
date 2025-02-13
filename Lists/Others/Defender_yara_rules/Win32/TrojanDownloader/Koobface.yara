rule TrojanDownloader_Win32_Koobface_A_2147804104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Koobface.A"
        threat_id = "2147804104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 6c 20 22 25 73 22 20 0a 20 25 73 20 22 25 73 22 20 67 6f 74 6f}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_3 = {0f 84 85 00 00 00 22 00 [0-4] 68 80 00 00 00 6a 02 53 53 ?? ?? ?? 40 00 68 00 00 00 40 ?? ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 68 61 72 54 6f 4f 65 6d 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 49 6e 69 74 69 61 6c 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {4d 6f 76 65 46 69 6c 65 45 78 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

