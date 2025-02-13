rule TrojanDownloader_Win32_Rirdra_2147687688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rirdra"
        threat_id = "2147687688"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rirdra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 31 31 35 2e 32 38 2e 33 32 2e 31 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 45 54 20 2f 37 2f 3f 72 3d 73 69 74 65 2f 47 54 43 44 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 31 31 35 2e 32 38 2e 33 32 2e 31 32 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = "SHGetFolderPathA" ascii //weight: 1
        $x_1_4 = "UninitializeCom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

