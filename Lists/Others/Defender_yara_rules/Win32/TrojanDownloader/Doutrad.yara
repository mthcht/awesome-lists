rule TrojanDownloader_Win32_Doutrad_B_2147630179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doutrad.B"
        threat_id = "2147630179"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doutrad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 06 32 d1 88 10 40 4f 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {eb 16 6a 00 8d 4c 24 0c 6a 1a 51 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {b9 41 00 00 00 33 c0 8d 7c 24 08 6a ff f3 ab b9 41 00 00 00 8d bc 24 10 01 00 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

