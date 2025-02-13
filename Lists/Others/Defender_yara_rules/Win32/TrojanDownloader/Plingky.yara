rule TrojanDownloader_Win32_Plingky_A_2147643330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Plingky.A"
        threat_id = "2147643330"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Plingky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 00 00 00 10 89 34 24 e8 ?? ?? ?? ?? 83 ec 1c 89 c2 83 f8 ff 74 77 31 c0 83 c9 ff 89 df f2 ae f7 d1 49 c7 44 24 10 00 00 00 00 8d 45 e4 89 44 24 0c 89 4c 24 08 89 5c 24 04 89 14 24 89 95 d4 fc ff ff e8 ?? ?? ?? ?? 83 ec 14 8b 95 d4 fc ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c ?? ?? ?? ?? 89 74 24 08 c7 44 24 04 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 83 ec 18 8d 65 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Plingky_C_2147654861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Plingky.C"
        threat_id = "2147654861"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Plingky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 4d 77 61 72 65 [0-4] 69 6e 73 74 61 6c 6c 5f 63 6f 6e 66 69 67 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_2 = {76 09 8b c7 80 36 02 46 48 75 f9 6a 66}  //weight: 1, accuracy: High
        $x_1_3 = "wor1,1741:,amo830;01" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

