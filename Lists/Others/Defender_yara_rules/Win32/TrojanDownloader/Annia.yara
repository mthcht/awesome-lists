rule TrojanDownloader_Win32_Annia_A_2147706191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Annia.A"
        threat_id = "2147706191"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Annia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 82 23 00 00 68 ?? ?? 40 00 ff 15 59 22 da 2d 4e 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = "uggc://46.148.19.74/ni.rkr" ascii //weight: 1
        $x_1_3 = {53 53 6a 03 53 6a 03 53 68 ?? ?? 40 00 c7 45 64 ?? ?? 40 00 c7 45 68 ?? ?? 40 00 c7 45 6c ?? ?? 40 00 89 5d 70 ff 15 bb a0 ae 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Annia_A_2147706191_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Annia.A"
        threat_id = "2147706191"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Annia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 04 0d eb 6e 8a 07 3c 4d 7f 1c 0f be c0 50 e8 ?? ?? ?? ?? 59 85 c0 74 0e 0f be 07 50 e8 ?? ?? ?? ?? 59 85 c0 75 d8 8a 07 3c 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {75 67 67 63 3a 2f 2f [0-16] 2f 6e 69 2e 72 6b 72}  //weight: 1, accuracy: Low
        $x_1_3 = {76 6d 77 61 72 65 00 00 76 69 72 74 75 61 6c 00 71 65 6d 75 00 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30}  //weight: 1, accuracy: High
        $x_1_4 = "JevgrSvyr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Annia_B_2147706977_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Annia.B"
        threat_id = "2147706977"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Annia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 82 23 00 00 89 ?? ?? ?? 8b f3 ff ?? ?? ?? ff d5 4e 75 f7}  //weight: 1, accuracy: Low
        $x_1_2 = "uggc://46.148.20.52/yx.rkr" ascii //weight: 1
        $x_1_3 = {53 53 6a 03 53 6a 03 53 68 ?? ?? 40 00 c7 45 64 ?? ?? 40 00 c7 45 68 ?? ?? 40 00 c7 45 6c ?? ?? 40 00 89 5d 70 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

