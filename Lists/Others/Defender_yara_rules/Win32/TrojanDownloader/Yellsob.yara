rule TrojanDownloader_Win32_Yellsob_A_2147608589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yellsob.A"
        threat_id = "2147608589"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yellsob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 2e 53 8b 5c 24 18 57 8a 44 14 10 8a 0c 1e 32 c8 8d 7c 24 10 88 0c 1e 83 c9 ff 33 c0 f2 ae f7 d1 8d 42 01 49 33 d2 f7 f1 46 3b f5 72 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Yellsob_A_2147608589_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yellsob.A"
        threat_id = "2147608589"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yellsob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2a 8b 4c 24 0c 53 8b 5c 24 18 55 8b 6c 24 20 56 8b 74 24 14 2b f1 8a 04 0e 32 04 1a 88 01 8d 42 01 99 f7 fd 41 4f 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 52 68 23 e2 22 00 50 56 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {68 30 75 00 00 8b f0 ff d7 6a 00 6a 00 6a 10 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 10 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 61 79 61 42 61 62 79 44 6c 6c 2e 64 6c 6c 00 43 6c 65 61 72 41 56 00 44 6f 57 6f 72 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

