rule TrojanDownloader_Win32_AutoIt_2147744760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AutoIt!MSR"
        threat_id = "2147744760"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoIt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6a 00 6f 00 62 00 73 00 6f 00 66 00 74 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 74 00 6d 00 70 00 2f 00 76 00 32 00 2f 00 7a 00 7a 00 7a 00 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-64] 20 00 26 00 20 00 22 00 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_4_2 = {52 00 55 00 4e 00 57 00 41 00 49 00 54 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-64] 20 00 26 00 20 00 22 00 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_1_3 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6a 00 6f 00 62 00 73 00 6f 00 66 00 74 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 6c 00 6c 00 2f 00 69 00 73 00 2f 00 64 00 6f 00 65 00 75 00 73 00 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-48] 20 00 26 00 20 00 22 00 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

