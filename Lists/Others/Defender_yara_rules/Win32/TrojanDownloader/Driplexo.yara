rule TrojanDownloader_Win32_Driplexo_A_2147689367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Driplexo.A"
        threat_id = "2147689367"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Driplexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3b 52 75 48 33 c0 80 7b 01 43}  //weight: 1, accuracy: High
        $x_1_2 = {32 04 29 88 04 0f 74 07 42 41 83 fa 30 72 db}  //weight: 1, accuracy: High
        $x_1_3 = {75 0e 83 f8 02 76 09 0b 00 8a d0 80 ea ?? 30 90}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 25 63 2f 25 63 25 63 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

