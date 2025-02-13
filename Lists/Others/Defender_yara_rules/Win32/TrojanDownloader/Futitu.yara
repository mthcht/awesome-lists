rule TrojanDownloader_Win32_Futitu_A_2147629627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Futitu.A"
        threat_id = "2147629627"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Futitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 63 6f 75 6e 74 2e 61 73 70 3f 61 63 74 3d 69 6e 73 74 61 6c 6c 26 65 78 65 63 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 63 6f 75 6e 74 5f 6c 69 76 65 2e 61 73 70 3f 65 78 65 63 3d 58 54 75 6e 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 58 54 75 6e 65 5c 58 54 75 6e 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 44 24 10 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 0a e8 ?? ?? ?? ?? a2 ?? ?? ?? ?? 68 88 13 00 00 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

