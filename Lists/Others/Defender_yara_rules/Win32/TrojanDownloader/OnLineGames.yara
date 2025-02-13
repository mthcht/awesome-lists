rule TrojanDownloader_Win32_OnLineGames_C_2147679078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/OnLineGames.C"
        threat_id = "2147679078"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 6c 65 72 74 65 72 20 43 4f 4d 2b 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 41 43 4b 54 49 4d 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 57 69 6e 64 6f 77 73 78 70 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 68 00 00 00 04 6a 00 6a 00 (50|51|56|57) (56|57) ff (d3|d5) 8b d0 85 d2}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 08 2a ca 32 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_6 = "txx|B//" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

