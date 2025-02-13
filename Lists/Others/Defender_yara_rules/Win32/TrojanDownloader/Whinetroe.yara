rule TrojanDownloader_Win32_Whinetroe_A_2147623514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Whinetroe.A"
        threat_id = "2147623514"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Whinetroe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 48 0c 2b 48 14 8d 04 39 8a 4d d4 30 08 47 6a 02 58 01 45 e0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {4d 53 48 54 4d 4c 44 45 2e 44 4c 4c 00 44 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

