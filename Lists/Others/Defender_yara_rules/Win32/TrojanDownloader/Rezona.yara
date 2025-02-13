rule TrojanDownloader_Win32_Rezona_RA_2147760708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rezona.RA!MTB"
        threat_id = "2147760708"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rezona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PoWeRsHeLl" ascii //weight: 1
        $x_5_2 = {28 6e 45 77 2d 4f 62 4a 65 43 74 20 4e 65 54 2e 57 65 62 43 6c 49 65 4e 74 29 2e 44 6f 57 6e 4c 6f 41 64 46 69 4c 65 28 27 68 74 74 70 3a 2f 2f [0-16] 2f [0-32] 2e [0-4] 27 2c 20 27 [0-32] 5c 01 2e 02 27 29 20 26}  //weight: 5, accuracy: Low
        $x_5_3 = {28 77 67 65 74 20 27 68 74 74 70 [0-16] 2f [0-10] 27 20 2d 4f 75 74 46 69 6c 65 20 [0-2] 5c [0-10] 5c [0-10] 2e 65 78 65 29}  //weight: 5, accuracy: Low
        $x_4_4 = {73 54 61 52 74 20 [0-2] 5c [0-10] 5c [0-10] 5c [0-32] 2e}  //weight: 4, accuracy: Low
        $x_4_5 = {70 4f 77 45 72 53 68 45 6c 4c 20 2d 77 49 6e 20 31 20 2d 63 20 22 49 45 58 20 28 4e 65 57 2d 6f 42 6a 45 63 54 20 6e 45 74 2e 57 65 42 43 6c 49 65 4e 74 29 2e 44 6f 57 6e 4c 6f 41 64 53 74 52 69 4e 67 28 27 68 74 74 70 3a 2f 2f [0-16] 2f [0-32] 2e [0-4] 27 29 22}  //weight: 4, accuracy: Low
        $x_4_6 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 50 61 73 73 20 2d 46 69 6c 65 20 [0-32] 20 26 20 53 54 41 52 54 20 2f 4d 49 4e 20 [0-32] 2e 65 78 65}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

