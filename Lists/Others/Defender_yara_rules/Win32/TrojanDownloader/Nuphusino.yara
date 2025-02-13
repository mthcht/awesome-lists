rule TrojanDownloader_Win32_Nuphusino_A_2147641978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nuphusino.A"
        threat_id = "2147641978"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuphusino"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 75 73 65 72 4e 61 6d 65 3d 25 73 26 63 6f 6d 70 4e 61 6d 65 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 73 6f 70 68 69 61 2f 69 6e 66 6f 33 32 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 6f 70 68 69 61 5c 53 6f 70 68 69 61 5c 53 6f 70 68 69 61 5c 52 65 6c 65 61 73 65 5c 53 6f 70 68 69 61 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

