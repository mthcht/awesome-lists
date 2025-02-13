rule TrojanDownloader_Win32_Slupim_A_2147602126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Slupim.A"
        threat_id = "2147602126"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Slupim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 44 24 10 01 e9 0c ff ff ff 89 6c 24 10 89 6c 24 14 89 6c 24 18 89 6c 24 24 8b 6c 24 28 68 ?? ?? 00 10 55 33 db e8}  //weight: 4, accuracy: Low
        $x_4_2 = {50 89 5c 24 1c 89 5c 24 20 89 7c 24 ?? 89 7c 24 30 e8 ?? ?? 00 00 8b f0 83 c4 08 3b f7 74 3d 68 ?? ?? 00 10 ff d5}  //weight: 4, accuracy: Low
        $x_1_3 = {53 52 56 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4c 50 3a 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 4f 44 3a 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 6f 64 3d 25 73 26 69 64 3d 25 73 5f 25 64 26 75 70 3d 25 64 26 6d 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 74 74 70 3a 2f 2f 25 73 2f 62 74 2e 70 68 70 3f 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

