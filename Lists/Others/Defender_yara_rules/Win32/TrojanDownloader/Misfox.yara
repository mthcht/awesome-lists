rule TrojanDownloader_Win32_Misfox_A_2147717054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Misfox.A"
        threat_id = "2147717054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Misfox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 10, accuracy: High
        $x_10_2 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 88 11 41 80 39 00 75 c6}  //weight: 10, accuracy: High
        $x_1_3 = {59 3a 5c 00 58 3a 5c 00 5a 3a 5c 00 48 3a 5c 00 47 3a 5c 00 46 3a 5c 00 45 3a 5c 00 44 3a 5c 00 43 3a 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f}  //weight: 1, accuracy: Low
        $x_1_5 = "bing.com" ascii //weight: 1
        $x_1_6 = "NJB#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

